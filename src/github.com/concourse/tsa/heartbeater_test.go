package tsa_test

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"code.cloudfoundry.org/clock/fakeclock"
	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/garden/gardenfakes"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/lager/lagertest"
	"github.com/concourse/atc"
	"github.com/concourse/baggageclaim"
	"github.com/concourse/baggageclaim/baggageclaimfakes"
	. "github.com/concourse/tsa"
	"github.com/concourse/tsa/tsafakes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/ghttp"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/rata"
)

var _ = Describe("Heartbeater", func() {
	type registration struct {
		worker atc.Worker
		ttl    time.Duration
	}

	var (
		logger   lager.Logger
		logLevel lager.LogLevel

		addrToRegister string
		fakeClock      *fakeclock.FakeClock
		interval       time.Duration
		cprInterval    time.Duration
		resourceTypes  []atc.WorkerResourceType

		expectedWorker         atc.Worker
		fakeTokenGenerator     *tsafakes.FakeTokenGenerator
		fakeGardenClient       *gardenfakes.FakeClient
		fakeBaggageclaimClient *baggageclaimfakes.FakeClient
		fakeATC1               *ghttp.Server
		fakeATC2               *ghttp.Server
		atcEndpointPicker      *tsafakes.FakeEndpointPicker
		heartbeater            ifrit.Process

		verifyRegister  http.HandlerFunc
		verifyHeartbeat http.HandlerFunc

		registrations <-chan registration
		heartbeats    <-chan registration
		clientWriter  *gbytes.Buffer

		worker atc.Worker
	)

	BeforeEach(func() {
		logger = lagertest.NewTestLogger("test")
		logLevel = lager.DEBUG

		addrToRegister = "1.2.3.4:7777"
		fakeClock = fakeclock.NewFakeClock(time.Unix(123, 456))
		interval = time.Second
		cprInterval = 100 * time.Millisecond
		resourceTypes = []atc.WorkerResourceType{
			{
				Type:  "git",
				Image: "/path/to/git/resource",
			},
		}

		worker = atc.Worker{
			Name:          "some-name",
			GardenAddr:    addrToRegister,
			ResourceTypes: resourceTypes,
			Platform:      "some-platform",
			Tags:          []string{"some", "tags"},
		}

		expectedWorker = worker

		fakeATC1 = ghttp.NewServer()
		fakeATC2 = ghttp.NewServer()

		registerRoute, found := atc.Routes.FindRouteByName(atc.RegisterWorker)
		Expect(found).To(BeTrue())

		registered := make(chan registration, 100)
		registrations = registered

		heartbeated := make(chan registration, 100)
		heartbeats = heartbeated

		verifyRegister = ghttp.CombineHandlers(
			ghttp.VerifyRequest(registerRoute.Method, registerRoute.Path),
			func(w http.ResponseWriter, r *http.Request) {
				var worker atc.Worker
				Expect(r.Header.Get("Authorization")).To(Equal("Bearer yo"))

				err := json.NewDecoder(r.Body).Decode(&worker)
				Expect(err).NotTo(HaveOccurred())

				ttl, err := time.ParseDuration(r.URL.Query().Get("ttl"))
				Expect(err).NotTo(HaveOccurred())

				registered <- registration{worker, ttl}
			},
		)

		verifyHeartbeat = ghttp.CombineHandlers(
			ghttp.VerifyRequest("PUT", "/api/v1/workers/some-name/heartbeat"),
			func(w http.ResponseWriter, r *http.Request) {
				var worker atc.Worker
				Expect(r.Header.Get("Authorization")).To(Equal("Bearer yo"))

				err := json.NewDecoder(r.Body).Decode(&worker)
				Expect(err).NotTo(HaveOccurred())

				ttl, err := time.ParseDuration(r.URL.Query().Get("ttl"))
				Expect(err).NotTo(HaveOccurred())

				heartbeated <- registration{worker, ttl}

				json.NewEncoder(w).Encode(atc.Worker{})
			},
		)

		fakeGardenClient = new(gardenfakes.FakeClient)
		fakeBaggageclaimClient = new(baggageclaimfakes.FakeClient)
		fakeTokenGenerator = new(tsafakes.FakeTokenGenerator)

		fakeTokenGenerator.GenerateSystemTokenReturns("yo", nil)
		fakeTokenGenerator.GenerateTeamTokenReturns("yo", nil)
		clientWriter = gbytes.NewBuffer()

		pickCallCount := 0
		atcEndpointPicker = new(tsafakes.FakeEndpointPicker)
		atcEndpointPicker.PickStub = func() *rata.RequestGenerator {
			pickCallCount++

			if pickCallCount%2 == 0 {
				return rata.NewRequestGenerator(fakeATC2.URL(), atc.Routes)
			}

			return rata.NewRequestGenerator(fakeATC1.URL(), atc.Routes)
		}
	})

	JustBeforeEach(func() {
		heartbeater = ifrit.Invoke(
			NewHeartbeater(
				logger,
				logLevel,
				fakeClock,
				interval,
				cprInterval,
				fakeGardenClient,
				fakeBaggageclaimClient,
				atcEndpointPicker,
				fakeTokenGenerator,
				worker,
				clientWriter,
			),
		)
	})

	AfterEach(func() {
		heartbeater.Signal(os.Interrupt)
		<-heartbeater.Wait()
		fakeATC2.Close()
		fakeATC1.Close()
	})

	Context("when Garden returns containers and Baggageclaim returns volumes", func() {
		BeforeEach(func() {
			containers := make(chan []garden.Container, 4)
			volumes := make(chan []baggageclaim.Volume, 4)

			containers <- []garden.Container{
				new(gardenfakes.FakeContainer),
				new(gardenfakes.FakeContainer),
			}

			volumes <- []baggageclaim.Volume{
				new(baggageclaimfakes.FakeVolume),
				new(baggageclaimfakes.FakeVolume),
				new(baggageclaimfakes.FakeVolume),
			}

			containers <- []garden.Container{
				new(gardenfakes.FakeContainer),
				new(gardenfakes.FakeContainer),
				new(gardenfakes.FakeContainer),
				new(gardenfakes.FakeContainer),
				new(gardenfakes.FakeContainer),
			}

			volumes <- []baggageclaim.Volume{
				new(baggageclaimfakes.FakeVolume),
				new(baggageclaimfakes.FakeVolume),
			}

			containers <- []garden.Container{
				new(gardenfakes.FakeContainer),
				new(gardenfakes.FakeContainer),
				new(gardenfakes.FakeContainer),
				new(gardenfakes.FakeContainer),
			}

			volumes <- []baggageclaim.Volume{
				new(baggageclaimfakes.FakeVolume),
			}

			containers <- []garden.Container{
				new(gardenfakes.FakeContainer),
				new(gardenfakes.FakeContainer),
				new(gardenfakes.FakeContainer),
			}

			volumes <- []baggageclaim.Volume{}

			close(containers)
			close(volumes)

			fakeGardenClient.ContainersStub = func(garden.Properties) ([]garden.Container, error) {
				return <-containers, nil
			}

			fakeBaggageclaimClient.ListVolumesStub = func(lager.Logger, baggageclaim.VolumeProperties) (baggageclaim.Volumes, error) {
				return <-volumes, nil
			}
		})

		Context("when the ATC responds to registration requests", func() {
			Context("When the DEBUG log level is set", func() {
				BeforeEach(func() {
					fakeATC1.AppendHandlers(verifyRegister)
					fakeATC2.AppendHandlers(verifyHeartbeat)
				})

				It("immediately registers", func() {
					expectedWorker.ActiveContainers = 2
					expectedWorker.ActiveVolumes = 3
					Expect(registrations).To(Receive(Equal(registration{expectedWorker, 2 * interval})))
				})

				It("heartbeats", func() {
					Expect(registrations).To(Receive())

					fakeClock.WaitForWatcherAndIncrement(interval)
					expectedWorker.ActiveContainers = 5
					expectedWorker.ActiveVolumes = 2
					Eventually(heartbeats).Should(Receive(Equal(registration{expectedWorker, 2 * interval})))
				})

				It("logs debug messages", func() {
					Expect(clientWriter).Should(gbytes.Say("test.register.start"))
					Expect(clientWriter).Should(gbytes.Say("test.register.reached-worker"))
					Expect(clientWriter).Should(gbytes.Say("test.register.done"))

					fakeClock.WaitForWatcherAndIncrement(interval)
					Eventually(clientWriter).Should(gbytes.Say("test.heartbeat.start"))
					Eventually(clientWriter).Should(gbytes.Say("test.heartbeat.reached-worker"))
					Eventually(clientWriter).Should(gbytes.Say("test.heartbeat.done"))
				})
			})

			Context("When the ERROR log level is set", func() {
				BeforeEach(func() {
					fakeATC1.AppendHandlers(verifyRegister)
					fakeATC2.AppendHandlers(verifyHeartbeat)
					logLevel = lager.ERROR
				})

				It("does not log messages", func() {
					Expect(clientWriter).ShouldNot(gbytes.Say("test.register.start"))
					Expect(clientWriter).ShouldNot(gbytes.Say("test.register.reached-worker"))
					Expect(clientWriter).ShouldNot(gbytes.Say("test.register.done"))

					fakeClock.WaitForWatcherAndIncrement(interval)
					Eventually(clientWriter).ShouldNot(gbytes.Say("test.heartbeat.start"))
					Eventually(clientWriter).ShouldNot(gbytes.Say("test.heartbeat.reached-worker"))
					Eventually(clientWriter).ShouldNot(gbytes.Say("test.heartbeat.done"))
				})
			})

		})

		Context("when heartbeat returns worker is landed", func() {
			BeforeEach(func() {
				heartbeated := make(chan registration, 100)
				heartbeats = heartbeated

				fakeATC1.AppendHandlers(verifyRegister)
				fakeATC2.AppendHandlers(ghttp.CombineHandlers(
					ghttp.VerifyRequest("PUT", "/api/v1/workers/some-name/heartbeat"),
					func(w http.ResponseWriter, r *http.Request) {
						var worker atc.Worker
						Expect(r.Header.Get("Authorization")).To(Equal("Bearer yo"))

						err := json.NewDecoder(r.Body).Decode(&worker)
						Expect(err).NotTo(HaveOccurred())

						ttl, err := time.ParseDuration(r.URL.Query().Get("ttl"))
						Expect(err).NotTo(HaveOccurred())

						heartbeated <- registration{worker, ttl}

						json.NewEncoder(w).Encode(atc.Worker{
							State: "landed",
						})
					},
				))
			})

			It("exits heartbeater with no error", func() {
				Expect(registrations).To(Receive())

				fakeClock.WaitForWatcherAndIncrement(interval)
				Eventually(heartbeats).Should(Receive())

				err := <-heartbeater.Wait()
				Expect(err).To(BeNil())
			})
		})

		Context("when the ATC doesn't respond to the first heartbeat", func() {
			BeforeEach(func() {
				fakeATC1.AppendHandlers(
					verifyRegister,
					verifyHeartbeat,
				)
				fakeATC2.AppendHandlers(
					ghttp.CombineHandlers(
						verifyHeartbeat,
						func(w http.ResponseWriter, r *http.Request) { fakeATC2.CloseClientConnections() },
					),
					verifyHeartbeat,
				)
			})

			It("heartbeats faster according to cprInterval", func() {
				Expect(registrations).To(Receive())

				fakeClock.WaitForWatcherAndIncrement(interval)
				Eventually(heartbeats).Should(Receive())

				fakeClock.WaitForWatcherAndIncrement(cprInterval)
				expectedWorker.ActiveContainers = 4
				expectedWorker.ActiveVolumes = 1
				Eventually(heartbeats).Should(Receive(Equal(registration{expectedWorker, 2 * interval})))
			})

			It("goes back to normal after the heartbeat succeeds", func() {
				Expect(registrations).To(Receive())

				fakeClock.WaitForWatcherAndIncrement(interval)
				Eventually(heartbeats).Should(Receive())

				fakeClock.WaitForWatcherAndIncrement(cprInterval)
				Eventually(heartbeats).Should(Receive())

				fakeClock.WaitForWatcherAndIncrement(cprInterval)
				Consistently(heartbeats).ShouldNot(Receive())

				fakeClock.WaitForWatcherAndIncrement(interval - cprInterval)
				expectedWorker.ActiveContainers = 3
				expectedWorker.ActiveVolumes = 0
				Eventually(heartbeats).Should(Receive(Equal(registration{expectedWorker, 2 * interval})))
			})
		})
	})
})
