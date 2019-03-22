package main_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"code.cloudfoundry.org/garden"
	gclient "code.cloudfoundry.org/garden/client"
	gconn "code.cloudfoundry.org/garden/client/connection"
	gfakes "code.cloudfoundry.org/garden/gardenfakes"
	gserver "code.cloudfoundry.org/garden/server"
	"code.cloudfoundry.org/lager/lagertest"
	"code.cloudfoundry.org/localip"
	"github.com/concourse/atc"
	"github.com/concourse/atc/api/accessor"
	"github.com/concourse/baggageclaim"
	"github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/ssh"

	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/onsi/gomega/ghttp"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration Suite")
}

var tsaPath string

var _ = BeforeSuite(func() {
	var err error
	tsaPath, err = gexec.Build("github.com/concourse/tsa/cmd/tsa")

	Expect(err).NotTo(HaveOccurred())
})

var _ = AfterSuite(func() {
	gexec.CleanupBuildArtifacts()
})

func generateSSHKeypair() (string, string) {
	path, err := ioutil.TempDir("", "tsa-key")
	Expect(err).NotTo(HaveOccurred())

	privateKey := filepath.Join(path, "id_rsa")

	keygen := exec.Command(
		"ssh-keygen",
		"-t", "rsa",
		"-N", "",
		"-f", privateKey,
	)

	keygenS, err := gexec.Start(keygen, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())

	keygenS.Wait(5 * time.Second)

	return privateKey, privateKey + ".pub"
}

var _ = Describe("TSA SSH Registrar", func() {
	Describe("registering workers with ATC", func() {
		var (
			forwardHost string

			tsaPort           int
			tsaDebugPort      int
			heartbeatInterval = 1 * time.Second
			tsaProcess        ifrit.Process

			gardenAddr  string
			fakeBackend *gfakes.FakeBackend

			gardenServer       *gserver.GardenServer
			baggageclaimServer *ghttp.Server
			atcServer          *ghttp.Server

			hostKey    string
			hostKeyPub string

			accessFactory          accessor.AccessFactory
			authorizedKeysFile     string
			teamAuthorizedKeysFile string

			userKnownHostsFile string

			userKey     string
			teamUserKey string

			tsaRunner *ginkgomon.Runner
		)

		BeforeEach(func() {
			tsaPort = 9800 + GinkgoParallelNode()
			tsaDebugPort = 9900 + GinkgoParallelNode()

			gardenPort := 9001 + GinkgoParallelNode()
			gardenAddr = fmt.Sprintf("127.0.0.1:%d", gardenPort)

			fakeBackend = new(gfakes.FakeBackend)

			gardenServer = gserver.New("tcp", gardenAddr, 0, fakeBackend, lagertest.NewTestLogger("garden"))
			go func() {
				defer GinkgoRecover()
				err := gardenServer.ListenAndServe()
				Expect(err).NotTo(HaveOccurred())
			}()

			apiClient := gclient.New(gconn.New("tcp", gardenAddr))
			Eventually(apiClient.Ping).Should(Succeed())

			err := gardenServer.SetupBomberman()
			Expect(err).NotTo(HaveOccurred())

			baggageclaimServer = ghttp.NewServer()

			atcServer = ghttp.NewServer()

			hostKey, hostKeyPub = generateSSHKeypair()

			userKnownHosts, err := ioutil.TempFile("", "known-hosts")
			Expect(err).NotTo(HaveOccurred())

			defer userKnownHosts.Close()

			userKnownHostsFile = userKnownHosts.Name()

			_, err = fmt.Fprintf(userKnownHosts, "[127.0.0.1]:%d ", tsaPort)
			Expect(err).NotTo(HaveOccurred())

			pub, err := os.Open(hostKeyPub)
			Expect(err).NotTo(HaveOccurred())

			defer pub.Close()

			_, err = io.Copy(userKnownHosts, pub)
			Expect(err).NotTo(HaveOccurred())

			userKey, _ = generateSSHKeypair()

			authorizedKeys, err := ioutil.TempFile("", "authorized-keys")
			Expect(err).NotTo(HaveOccurred())

			defer authorizedKeys.Close()

			authorizedKeysFile = authorizedKeys.Name()

			userPrivateKeyBytes, err := ioutil.ReadFile(userKey)
			Expect(err).NotTo(HaveOccurred())

			userSigner, err := ssh.ParsePrivateKey(userPrivateKeyBytes)
			Expect(err).NotTo(HaveOccurred())

			_, err = authorizedKeys.Write(ssh.MarshalAuthorizedKey(userSigner.PublicKey()))
			Expect(err).NotTo(HaveOccurred())

			teamAuthorizedKeys, err := ioutil.TempFile("", "exampleteam_authorized_keys")
			Expect(err).NotTo(HaveOccurred())

			defer teamAuthorizedKeys.Close()

			teamAuthorizedKeysFile = teamAuthorizedKeys.Name()

			teamUserKey, _ = generateSSHKeypair()

			teamUserKeyBytes, err := ioutil.ReadFile(teamUserKey)
			Expect(err).NotTo(HaveOccurred())

			teamSigner, err := ssh.ParsePrivateKey(teamUserKeyBytes)
			Expect(err).NotTo(HaveOccurred())

			_, err = teamAuthorizedKeys.Write(ssh.MarshalAuthorizedKey(teamSigner.PublicKey()))
			Expect(err).NotTo(HaveOccurred())

			forwardHost, err = localip.LocalIP()
			Expect(err).NotTo(HaveOccurred())

			sessionSigningPrivateKeyFile, _ := generateSSHKeypair()
			rsaKeyBlob, err := ioutil.ReadFile(string(sessionSigningPrivateKeyFile))
			Expect(err).NotTo(HaveOccurred())

			signingKey, err := jwt.ParseRSAPrivateKeyFromPEM(rsaKeyBlob)
			Expect(err).NotTo(HaveOccurred())

			accessFactory = accessor.NewAccessFactory(&signingKey.PublicKey)

			tsaCommand := exec.Command(
				tsaPath,
				"--bind-port", strconv.Itoa(tsaPort),
				"--bind-debug-port", strconv.Itoa(tsaDebugPort),
				"--peer-ip", forwardHost,
				"--host-key", hostKey,
				"--authorized-keys", authorizedKeysFile,
				"--team-authorized-keys", "exampleteam="+teamAuthorizedKeysFile,
				"--session-signing-key", sessionSigningPrivateKeyFile,
				"--atc-url", atcServer.URL(),
				"--heartbeat-interval", heartbeatInterval.String(),
			)

			tsaRunner = ginkgomon.New(ginkgomon.Config{
				Command:       tsaCommand,
				Name:          "tsa",
				StartCheck:    "tsa.listening",
				AnsiColorCode: "32m",
			})

			tsaProcess = ginkgomon.Invoke(tsaRunner)
		})

		AfterEach(func() {
			atcServer.Close()
			gardenServer.Stop()
			ginkgomon.Interrupt(tsaProcess)
		})

		Describe("SSHing", func() {
			var sshSess *gexec.Session
			var sshStdin io.Writer
			var sshArgv []string

			BeforeEach(func() {
				sshArgv = []string{
					"127.0.0.1",
					"-p", strconv.Itoa(tsaPort),
					"-o", "UserKnownHostsFile=" + userKnownHostsFile,
				}
			})

			JustBeforeEach(func() {
				ssh := exec.Command("ssh", sshArgv...)

				var err error
				sshStdin, err = ssh.StdinPipe()
				Expect(err).NotTo(HaveOccurred())

				sshSess, err = gexec.Start(
					ssh,
					gexec.NewPrefixedWriter("\x1b[32m[o]\x1b[0m\x1b[33m[ssh]\x1b[0m ", GinkgoWriter),
					gexec.NewPrefixedWriter("\x1b[91m[e]\x1b[0m\x1b[33m[ssh]\x1b[0m ", GinkgoWriter),
				)
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				sshSess.Interrupt().Wait(10 * time.Second)
			})

			Context("with a globally authorized key", func() {
				BeforeEach(func() {
					sshArgv = append(sshArgv, "-i", userKey)
				})

				Context("when running register-worker", func() {
					BeforeEach(func() {
						sshArgv = append(sshArgv, "register-worker")
					})

					It("does not exit", func() {
						Consistently(sshSess, 1).ShouldNot(gexec.Exit())
					})

					Describe("sending a worker payload on stdin", func() {
						type registration struct {
							worker atc.Worker
							ttl    time.Duration
						}

						var workerPayload atc.Worker
						var registered chan registration
						var heartbeated chan registration

						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",

								GardenAddr:      gardenAddr,
								BaggageclaimURL: baggageclaimServer.URL(),

								Platform: "linux",
								Tags:     []string{"some", "tags"},

								ResourceTypes: []atc.WorkerResourceType{
									{Type: "resource-type-a", Image: "resource-image-a"},
									{Type: "resource-type-b", Image: "resource-image-b"},
								},
							}

							registered = make(chan registration, 100)
							heartbeated = make(chan registration, 100)

							atcServer.RouteToHandler("POST", "/api/v1/workers", func(w http.ResponseWriter, r *http.Request) {
								var worker atc.Worker
								Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())

								err := json.NewDecoder(r.Body).Decode(&worker)
								Expect(err).NotTo(HaveOccurred())

								ttl, err := time.ParseDuration(r.URL.Query().Get("ttl"))
								Expect(err).NotTo(HaveOccurred())

								json.NewEncoder(w).Encode(worker)

								registered <- registration{worker, ttl}
							})

							atcServer.RouteToHandler("PUT", "/api/v1/workers/some-worker/heartbeat", func(w http.ResponseWriter, r *http.Request) {
								var worker atc.Worker
								Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())

								err := json.NewDecoder(r.Body).Decode(&worker)
								Expect(err).NotTo(HaveOccurred())

								ttl, err := time.ParseDuration(r.URL.Query().Get("ttl"))
								Expect(err).NotTo(HaveOccurred())

								heartbeated <- registration{worker, ttl}
							})

							gardenStubs := make(chan func() ([]garden.Container, error), 6)

							gardenStubs <- func() ([]garden.Container, error) {
								return []garden.Container{
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
								}, nil
							}

							gardenStubs <- func() ([]garden.Container, error) {
								return []garden.Container{
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
								}, nil
							}

							gardenStubs <- func() ([]garden.Container, error) {
								return nil, errors.New("garden was weeded")
							}

							gardenStubs <- func() ([]garden.Container, error) {
								return []garden.Container{
									new(gfakes.FakeContainer),
								}, nil
							}

							gardenStubs <- func() ([]garden.Container, error) {
								return []garden.Container{
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
								}, nil
							}

							gardenStubs <- func() ([]garden.Container, error) {
								return []garden.Container{
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
								}, nil
							}

							close(gardenStubs)

							fakeBackend.ContainersStub = func(garden.Properties) ([]garden.Container, error) {
								return (<-gardenStubs)()
							}

							baggageclaimServer.AppendHandlers(
								ghttp.CombineHandlers(
									ghttp.VerifyRequest("GET", "/volumes"),
									ghttp.RespondWithJSONEncoded(http.StatusOK, []baggageclaim.VolumeResponse{
										{Handle: "handle-a"},
										{Handle: "handle-b"},
									}),
								),
								ghttp.CombineHandlers(
									ghttp.VerifyRequest("GET", "/volumes"),
									ghttp.RespondWithJSONEncoded(http.StatusOK, []baggageclaim.VolumeResponse{
										{Handle: "handle-a"},
									}),
								),
								ghttp.CombineHandlers(
									ghttp.VerifyRequest("GET", "/volumes"),
									ghttp.RespondWithJSONEncoded(http.StatusOK, []baggageclaim.VolumeResponse{
										{Handle: "handle-a"},
										{Handle: "handle-b"},
										{Handle: "handle-c"},
									}),
								),
								ghttp.CombineHandlers(
									ghttp.VerifyRequest("GET", "/volumes"),
									ghttp.RespondWithJSONEncoded(http.StatusOK, []baggageclaim.VolumeResponse{}),
								),
								ghttp.CombineHandlers(
									ghttp.VerifyRequest("GET", "/volumes"),
									func(w http.ResponseWriter, r *http.Request) {
										baggageclaimServer.CloseClientConnections()
									},
								),
								ghttp.CombineHandlers(
									ghttp.VerifyRequest("GET", "/volumes"),
									ghttp.RespondWithJSONEncoded(http.StatusOK, []baggageclaim.VolumeResponse{
										{Handle: "handle-c"},
										{Handle: "handle-3"},
										{Handle: "handle-po"},
									}),
								),
							)
						})

						JustBeforeEach(func() {
							err := json.NewEncoder(sshStdin).Encode(workerPayload)
							Expect(err).NotTo(HaveOccurred())
						})

						It("continuously registers it with the ATC as long as it works", func() {
							expectedWorkerPayload := workerPayload

							expectedWorkerPayload.ActiveContainers = 3
							expectedWorkerPayload.ActiveVolumes = 2

							a := time.Now()
							Expect(<-registered).To(Equal(registration{
								worker: expectedWorkerPayload,
								ttl:    2 * heartbeatInterval,
							}))

							expectedWorkerPayload.ActiveContainers = 2
							expectedWorkerPayload.ActiveVolumes = 1

							b := time.Now()
							Expect(<-heartbeated).To(Equal(registration{
								worker: expectedWorkerPayload,
								ttl:    2 * heartbeatInterval,
							}))

							Expect(b.Sub(a)).To(BeNumerically("~", heartbeatInterval, 1*time.Second))

							Consistently(heartbeated, 2*heartbeatInterval).ShouldNot(Receive())

							expectedWorkerPayload.ActiveContainers = 1
							expectedWorkerPayload.ActiveVolumes = 0

							c := time.Now()
							Expect(<-heartbeated).To(Equal(registration{
								worker: expectedWorkerPayload,
								ttl:    2 * heartbeatInterval,
							}))

							Expect(c.Sub(b)).To(BeNumerically("~", 3*heartbeatInterval, 1*time.Second))

							Consistently(heartbeated, 2*heartbeatInterval).ShouldNot(Receive())

							expectedWorkerPayload.ActiveContainers = 6
							expectedWorkerPayload.ActiveVolumes = 3

							d := time.Now()
							Expect(<-heartbeated).To(Equal(registration{
								worker: expectedWorkerPayload,
								ttl:    2 * heartbeatInterval,
							}))

							Expect(d.Sub(c)).To(BeNumerically("~", 3*heartbeatInterval, 1*time.Second))

							Eventually(sshSess.Out).Should(gbytes.Say("heartbeat"))
						})

						Context("when the ATC returns a 404 for the heartbeat", func() {
							BeforeEach(func() {
								atcServer.RouteToHandler("PUT", "/api/v1/workers/some-worker/heartbeat", func(w http.ResponseWriter, r *http.Request) {
									Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
									w.WriteHeader(404)
								})
							})

							It("exits gracefully", func() {
								Eventually(sshSess, 3).Should(gexec.Exit(0))
							})
						})

						Context("when the client goes away", func() {
							It("stops registering", func() {
								time.Sleep(heartbeatInterval)

								sshSess.Interrupt().Wait(10 * time.Second)

								time.Sleep(heartbeatInterval)

								// siphon off any existing registrations
							dance:
								for {
									select {
									case <-registered:
									case <-heartbeated:
									default:
										break dance
									}
								}

								Consistently(registered, 2*heartbeatInterval).ShouldNot(Receive())
								Consistently(heartbeated, 2*heartbeatInterval).ShouldNot(Receive())
							})
						})
					})
				})

				Context("when running forward-worker with multiple forwarded addresses", func() {

					BeforeEach(func() {
						baggageclaimServer = ghttp.NewServer()

						sshArgv = append(
							sshArgv,
							"-R", fmt.Sprintf("0.0.0.0:7777:%s", gardenAddr),
							"-R", fmt.Sprintf("0.0.0.0:7788:%s", baggageclaimServer.Addr()),
							"forward-worker",
							"--garden", "0.0.0.0:7777",
							"--baggageclaim", "0.0.0.0:7788",
						)
					})

					It("does not exit", func() {
						Consistently(sshSess, 1).ShouldNot(gexec.Exit())
					})

					Describe("sending a worker payload on stdin", func() {
						type registration struct {
							worker atc.Worker
							ttl    time.Duration
						}

						var workerPayload atc.Worker
						var registered chan registration
						var heartbeated chan registration

						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name:     "some-worker",
								Platform: "linux",
								Tags:     []string{"some", "tags"},

								ResourceTypes: []atc.WorkerResourceType{
									{Type: "resource-type-a", Image: "resource-image-a"},
									{Type: "resource-type-b", Image: "resource-image-b"},
								},
							}

							registered = make(chan registration, 100)
							heartbeated = make(chan registration, 100)

							atcServer.RouteToHandler("POST", "/api/v1/workers", func(w http.ResponseWriter, r *http.Request) {
								var worker atc.Worker
								Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())

								err := json.NewDecoder(r.Body).Decode(&worker)
								Expect(err).NotTo(HaveOccurred())

								ttl, err := time.ParseDuration(r.URL.Query().Get("ttl"))
								Expect(err).NotTo(HaveOccurred())

								registered <- registration{worker, ttl}
							})

							atcServer.RouteToHandler("PUT", "/api/v1/workers/some-worker/heartbeat", func(w http.ResponseWriter, r *http.Request) {
								var worker atc.Worker
								Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())

								err := json.NewDecoder(r.Body).Decode(&worker)
								Expect(err).NotTo(HaveOccurred())

								ttl, err := time.ParseDuration(r.URL.Query().Get("ttl"))
								Expect(err).NotTo(HaveOccurred())

								heartbeated <- registration{worker, ttl}
							})

							gardenStubs := make(chan func() ([]garden.Container, error), 4)

							gardenStubs <- func() ([]garden.Container, error) {
								return []garden.Container{
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
								}, nil
							}

							gardenStubs <- func() ([]garden.Container, error) {
								return []garden.Container{
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
								}, nil
							}

							gardenStubs <- func() ([]garden.Container, error) {
								return nil, errors.New("garden was weeded")
							}

							gardenStubs <- func() ([]garden.Container, error) {
								return []garden.Container{
									new(gfakes.FakeContainer),
								}, nil
							}

							close(gardenStubs)

							fakeBackend.ContainersStub = func(garden.Properties) ([]garden.Container, error) {
								return (<-gardenStubs)()
							}

							baggageclaimServer.AppendHandlers(
								ghttp.CombineHandlers(
									ghttp.VerifyRequest("GET", "/volumes"),
									ghttp.RespondWithJSONEncoded(http.StatusOK, []baggageclaim.VolumeResponse{
										{Handle: "handle-a"},
										{Handle: "handle-b"},
									}),
								),
								ghttp.CombineHandlers(
									ghttp.VerifyRequest("GET", "/volumes"),
									ghttp.RespondWithJSONEncoded(http.StatusOK, []baggageclaim.VolumeResponse{
										{Handle: "handle-a"},
									}),
								),
								ghttp.CombineHandlers(
									ghttp.VerifyRequest("GET", "/volumes"),
									ghttp.RespondWithJSONEncoded(http.StatusOK, []baggageclaim.VolumeResponse{
										{Handle: "handle-a"},
										{Handle: "handle-b"},
										{Handle: "handle-c"},
									}),
								),
								ghttp.CombineHandlers(
									ghttp.VerifyRequest("GET", "/volumes"),
									ghttp.RespondWithJSONEncoded(http.StatusOK, []baggageclaim.VolumeResponse{}),
								),
							)

						})

						JustBeforeEach(func() {
							err := json.NewEncoder(sshStdin).Encode(workerPayload)
							Expect(err).NotTo(HaveOccurred())
						})

						It("forwards garden API calls through the tunnel", func() {
							registration := <-registered
							addr := registration.worker.GardenAddr

							client := gclient.New(gconn.New("tcp", addr))

							fakeBackend.CreateReturns(new(gfakes.FakeContainer), nil)

							_, err := client.Create(garden.ContainerSpec{})
							Expect(err).NotTo(HaveOccurred())

							Expect(fakeBackend.CreateCallCount()).To(Equal(1))
						})

						It("continuously registers it with the ATC as long as it works", func() {
							a := time.Now()
							registration := <-registered
							Expect(registration.ttl).To(Equal(2 * heartbeatInterval))

							// shortcut for equality w/out checking addr
							expectedWorkerPayload := workerPayload
							expectedWorkerPayload.GardenAddr = registration.worker.GardenAddr
							expectedWorkerPayload.BaggageclaimURL = registration.worker.BaggageclaimURL
							expectedWorkerPayload.ActiveContainers = 3
							expectedWorkerPayload.ActiveVolumes = 2
							Expect(registration.worker).To(Equal(expectedWorkerPayload))

							host, _, err := net.SplitHostPort(registration.worker.GardenAddr)
							Expect(err).NotTo(HaveOccurred())
							Expect(host).To(Equal(forwardHost))

							b := time.Now()
							registration = <-heartbeated
							Expect(registration.ttl).To(Equal(2 * heartbeatInterval))

							// shortcut for equality w/out checking addr
							expectedWorkerPayload = workerPayload
							expectedWorkerPayload.GardenAddr = registration.worker.GardenAddr
							expectedWorkerPayload.BaggageclaimURL = registration.worker.BaggageclaimURL
							expectedWorkerPayload.ActiveContainers = 2
							expectedWorkerPayload.ActiveVolumes = 1
							Expect(registration.worker).To(Equal(expectedWorkerPayload))

							host, _, err = net.SplitHostPort(registration.worker.GardenAddr)
							Expect(err).NotTo(HaveOccurred())
							Expect(host).To(Equal(forwardHost))

							Expect(b.Sub(a)).To(BeNumerically("~", heartbeatInterval, 1*time.Second))

							Consistently(heartbeated, 2*heartbeatInterval).ShouldNot(Receive())

							c := time.Now()
							registration = <-heartbeated
							Expect(registration.ttl).To(Equal(2 * heartbeatInterval))

							// shortcut for equality w/out checking addr
							expectedWorkerPayload = workerPayload
							expectedWorkerPayload.GardenAddr = registration.worker.GardenAddr
							expectedWorkerPayload.BaggageclaimURL = registration.worker.BaggageclaimURL
							expectedWorkerPayload.ActiveContainers = 1
							expectedWorkerPayload.ActiveVolumes = 0
							Expect(registration.worker).To(Equal(expectedWorkerPayload))

							host, port, err := net.SplitHostPort(registration.worker.GardenAddr)
							Expect(err).NotTo(HaveOccurred())
							Expect(host).To(Equal(forwardHost))
							Expect(port).NotTo(Equal("7777")) // should NOT respect bind addr

							bURL, err := url.Parse(registration.worker.BaggageclaimURL)
							Expect(err).NotTo(HaveOccurred())

							host, port, err = net.SplitHostPort(bURL.Host)
							Expect(err).NotTo(HaveOccurred())
							Expect(host).To(Equal(forwardHost))
							Expect(port).NotTo(Equal("7788")) // should NOT respect bind addr

							Expect(c.Sub(b)).To(BeNumerically("~", 3*heartbeatInterval, 1*time.Second))
						})

						Context("when the ATC returns a 404 for the heartbeat", func() {
							BeforeEach(func() {
								atcServer.RouteToHandler("PUT", "/api/v1/workers/some-worker/heartbeat", func(w http.ResponseWriter, r *http.Request) {
									Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
									w.WriteHeader(404)
								})
							})

							It("exits gracefully", func() {
								Eventually(sshSess, 3).Should(gexec.Exit(0))
							})
						})

						Context("when the client goes away", func() {
							It("stops registering", func() {
								time.Sleep(heartbeatInterval)

								sshSess.Interrupt().Wait(10 * time.Second)

								time.Sleep(heartbeatInterval)

								// siphon off any existing registrations
							dance:
								for {
									select {
									case <-registered:
									case <-heartbeated:
									default:
										break dance
									}
								}

								Consistently(registered, 2*heartbeatInterval).ShouldNot(Receive())
								Consistently(heartbeated, 2*heartbeatInterval).ShouldNot(Receive())
							})
						})
					})
				})

				Context("when running land-worker", func() {
					var workerPayload atc.Worker

					BeforeEach(func() {
						sshArgv = append(sshArgv, "land-worker")
					})

					JustBeforeEach(func() {
						err := json.NewEncoder(sshStdin).Encode(workerPayload)
						Expect(err).NotTo(HaveOccurred())
					})

					Context("when the ATC is working", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
							}

							atcServer.AppendHandlers(ghttp.CombineHandlers(
								ghttp.VerifyRequest("PUT", "/api/v1/workers/some-worker/land"),
								http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
									Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
								}),
								ghttp.RespondWith(200, nil, nil),
							))
						})

						It("sends a request to the ATC to land the worker", func() {
							Eventually(sshSess, 3).Should(gexec.Exit(0))
							Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
						})
					})

					Context("when the ATC responds with a missing worker (404)", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
							}

							atcServer.AppendHandlers(ghttp.CombineHandlers(
								ghttp.VerifyRequest("PUT", "/api/v1/workers/some-worker/land"),
								http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
									Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
								}),
								ghttp.RespondWith(404, nil, nil),
							))
						})

						It("exits with failure", func() {
							Eventually(tsaRunner.Buffer()).Should(gbytes.Say("404"))
							Eventually(sshSess, 3).Should(gexec.Exit(1))
							Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
						})
					})

					Context("when the ATC responds with an error", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
							}

							atcServer.AppendHandlers(ghttp.CombineHandlers(
								ghttp.VerifyRequest("PUT", "/api/v1/workers/some-worker/land"),
								http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
									Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
								}),
								ghttp.RespondWith(500, nil, nil),
							))
						})

						It("exits with failure", func() {
							Eventually(tsaRunner.Buffer()).Should(gbytes.Say("500"))

							Eventually(sshSess, 3).Should(gexec.Exit(1))
							Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
						})
					})
				})

				Context("when running command to sweep containers", func() {
					var workerPayload atc.Worker

					BeforeEach(func() {
						sshArgv = append(sshArgv, "sweep-containers")
					})

					JustBeforeEach(func() {
						err := json.NewEncoder(sshStdin).Encode(workerPayload)
						Expect(err).NotTo(HaveOccurred())
					})

					Context("when the ATC is working", func() {
						BeforeEach(func() {
							expectedBody := []string{"handle1", "handle2"}
							data, err := json.Marshal(expectedBody)
							Ω(err).ShouldNot(HaveOccurred())

							workerPayload = atc.Worker{
								Name: "some-worker",
							}

							atcServer.AppendHandlers(ghttp.CombineHandlers(
								ghttp.VerifyRequest("GET", "/api/v1/containers/destroying"),
								http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
									Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
								}),
								ghttp.RespondWith(200, data, nil),
							))
						})

						It("sends a request to the ATC to land the worker", func() {
							Eventually(sshSess, 3).Should(gbytes.Say("handle1"))
							Eventually(sshSess, 3).Should(gbytes.Say("handle2"))

							Eventually(sshSess, 3).Should(gexec.Exit(0))
							Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
						})
					})

					Context("when the ATC responds with a missing worker (404)", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
							}

							atcServer.AppendHandlers(ghttp.CombineHandlers(
								ghttp.VerifyRequest("GET", "/api/v1/containers/destroying"),
								http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
									Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
								}),
								ghttp.RespondWith(404, nil, nil),
							))
						})

						It("exits with failure", func() {
							Eventually(tsaRunner.Buffer()).Should(gbytes.Say("404"))
							Eventually(sshSess, 3).Should(gexec.Exit(1))
							Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
						})
					})

					Context("when the ATC responds with an error", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
							}

							atcServer.AppendHandlers(ghttp.CombineHandlers(
								ghttp.VerifyRequest("GET", "/api/v1/containers/destroying"),
								http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
									Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
								}),
								ghttp.RespondWith(500, nil, nil),
							))
						})

						It("exits with failure", func() {
							Eventually(tsaRunner.Buffer()).Should(gbytes.Say("500"))

							Eventually(sshSess, 3).Should(gexec.Exit(1))
							Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
						})
					})
				})

				Context("when running command to sweep volumes", func() {
					var workerPayload atc.Worker

					BeforeEach(func() {
						sshArgv = append(sshArgv, "sweep-volumes")
					})

					JustBeforeEach(func() {
						err := json.NewEncoder(sshStdin).Encode(workerPayload)
						Expect(err).NotTo(HaveOccurred())
					})

					Context("when the ATC is working", func() {
						BeforeEach(func() {
							expectedBody := []string{"handle1", "handle2"}
							data, err := json.Marshal(expectedBody)
							Ω(err).ShouldNot(HaveOccurred())

							workerPayload = atc.Worker{
								Name: "some-worker",
							}

							atcServer.AppendHandlers(ghttp.CombineHandlers(
								ghttp.VerifyRequest("GET", "/api/v1/volumes/destroying"),
								http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
									Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
								}),
								ghttp.RespondWith(200, data, nil),
							))
						})

						It("sends a request to the ATC to land the worker", func() {
							Eventually(sshSess, 3).Should(gbytes.Say("handle1"))
							Eventually(sshSess, 3).Should(gbytes.Say("handle2"))

							Eventually(sshSess, 3).Should(gexec.Exit(0))
							Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
						})
					})

					Context("when the ATC responds with a missing worker (404)", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
							}

							atcServer.AppendHandlers(ghttp.CombineHandlers(
								ghttp.VerifyRequest("GET", "/api/v1/volumes/destroying"),
								http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
									Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
								}),
								ghttp.RespondWith(404, nil, nil),
							))
						})

						It("exits with failure", func() {
							Eventually(tsaRunner.Buffer()).Should(gbytes.Say("404"))
							Eventually(sshSess, 3).Should(gexec.Exit(1))
							Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
						})
					})

					Context("when the ATC responds with an error", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
							}

							atcServer.AppendHandlers(ghttp.CombineHandlers(
								ghttp.VerifyRequest("GET", "/api/v1/volumes/destroying"),
								http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
									Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
								}),
								ghttp.RespondWith(500, nil, nil),
							))
						})

						It("exits with failure", func() {
							Eventually(tsaRunner.Buffer()).Should(gbytes.Say("500"))

							Eventually(sshSess, 3).Should(gexec.Exit(1))
							Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
						})
					})
				})

				Context("when running command to report containers", func() {
					var workerPayload atc.Worker

					BeforeEach(func() {
						sshArgv = append(sshArgv, "report-containers")
					})

					JustBeforeEach(func() {
						err := json.NewEncoder(sshStdin).Encode(workerPayload)
						Expect(err).NotTo(HaveOccurred())
					})

					Context("when the ATC is working", func() {
						BeforeEach(func() {
							resp := []string{"handle1", "handle2"}

							workerPayload = atc.Worker{
								Name: "some-worker",
							}

							atcServer.AppendHandlers(ghttp.CombineHandlers(
								ghttp.VerifyRequest("PUT", "/api/v1/containers/report"),
								http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
									Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
								}),
								ghttp.RespondWithJSONEncoded(204, resp),
							))
						})

						It("sends a request to the ATC to report the worker containers", func() {
							Eventually(sshSess, 3).Should(gexec.Exit(0))
							Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
						})
					})

					Context("when the ATC responds with a missing worker (404)", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
							}

							atcServer.AppendHandlers(ghttp.CombineHandlers(
								ghttp.VerifyRequest("PUT", "/api/v1/containers/report"),
								http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
									Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
								}),
								ghttp.RespondWith(404, nil, nil),
							))
						})

						It("exits with failure", func() {
							Eventually(tsaRunner.Buffer()).Should(gbytes.Say("404"))
							Eventually(sshSess, 3).Should(gexec.Exit(1))
							Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
						})
					})

					Context("when the ATC responds with an error", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
							}

							atcServer.AppendHandlers(ghttp.CombineHandlers(
								ghttp.VerifyRequest("PUT", "/api/v1/containers/report"),
								http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
									Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
								}),
								ghttp.RespondWith(500, nil, nil),
							))
						})

						It("exits with failure", func() {
							Eventually(tsaRunner.Buffer()).Should(gbytes.Say("500"))
							Eventually(sshSess, 3).Should(gexec.Exit(1))
							Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
						})
					})
				})

				Context("when running command to report volumes", func() {
					var workerPayload atc.Worker

					BeforeEach(func() {
						sshArgv = append(sshArgv, "report-volumes")
					})

					JustBeforeEach(func() {
						err := json.NewEncoder(sshStdin).Encode(workerPayload)
						Expect(err).NotTo(HaveOccurred())
					})

					Context("when the ATC is working", func() {
						BeforeEach(func() {
							resp := []string{"handle1", "handle2"}

							workerPayload = atc.Worker{
								Name: "some-worker",
							}

							atcServer.AppendHandlers(ghttp.CombineHandlers(
								ghttp.VerifyRequest("PUT", "/api/v1/volumes/report"),
								http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
									Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
								}),
								ghttp.RespondWithJSONEncoded(204, resp),
							))
						})

						It("sends a request to the ATC to report the worker volumes", func() {
							Eventually(sshSess, 3).Should(gexec.Exit(0))
							Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
						})
					})

					Context("when the ATC responds with a missing worker (404)", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
							}

							atcServer.AppendHandlers(ghttp.CombineHandlers(
								ghttp.VerifyRequest("PUT", "/api/v1/volumes/report"),
								http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
									Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
								}),
								ghttp.RespondWith(404, nil, nil),
							))
						})

						It("exits with failure", func() {
							Eventually(tsaRunner.Buffer()).Should(gbytes.Say("404"))
							Eventually(sshSess, 3).Should(gexec.Exit(1))
							Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
						})
					})

					Context("when the ATC responds with an error", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
							}

							atcServer.AppendHandlers(ghttp.CombineHandlers(
								ghttp.VerifyRequest("PUT", "/api/v1/volumes/report"),
								http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
									Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
								}),
								ghttp.RespondWith(500, nil, nil),
							))
						})

						It("exits with failure", func() {
							Eventually(tsaRunner.Buffer()).Should(gbytes.Say("500"))
							Eventually(sshSess, 3).Should(gexec.Exit(1))
							Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
						})
					})
				})

				Context("when running a bogus command", func() {
					BeforeEach(func() {
						sshArgv = append(sshArgv, "bogus-command")
					})

					It("exits with failure", func() {
						Eventually(sshSess, 10).Should(gexec.Exit(255))
					})
				})
			})

			Context("with an invalid key", func() {
				BeforeEach(func() {
					badPrivKey, _ := generateSSHKeypair()
					sshArgv = append(sshArgv, "-i", badPrivKey)
				})

				It("exits with failure", func() {
					Eventually(sshSess, 10).Should(gexec.Exit(255))
				})
			})

			Context("with an authorized keys", func() {
				BeforeEach(func() {
					sshArgv = append(sshArgv, "-i", userKey)
				})

				Context("when running register-worker", func() {
					BeforeEach(func() {
						sshArgv = append(sshArgv, "register-worker")
					})

					It("does not exit", func() {
						Consistently(sshSess, 1).ShouldNot(gexec.Exit())
					})

					Context("sending a worker from the same team's payload on stdin", func() {
						type registration struct {
							worker atc.Worker
							ttl    time.Duration
						}

						var workerPayload atc.Worker
						var registered chan registration
						var heartbeated chan registration

						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",

								GardenAddr:      gardenAddr,
								BaggageclaimURL: baggageclaimServer.URL(),

								Platform: "linux",
								Tags:     []string{"some", "tags"},
								Team:     "another-exampleteam",

								ResourceTypes: []atc.WorkerResourceType{
									{Type: "resource-type-a", Image: "resource-image-a"},
									{Type: "resource-type-b", Image: "resource-image-b"},
								},
							}

							registered = make(chan registration, 100)
							heartbeated = make(chan registration, 100)

							atcServer.RouteToHandler("POST", "/api/v1/workers", func(w http.ResponseWriter, r *http.Request) {
								var worker atc.Worker
								Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())

								err := json.NewDecoder(r.Body).Decode(&worker)
								Expect(err).NotTo(HaveOccurred())

								ttl, err := time.ParseDuration(r.URL.Query().Get("ttl"))
								Expect(err).NotTo(HaveOccurred())

								json.NewEncoder(w).Encode(worker)

								registered <- registration{worker, ttl}
							})

							atcServer.RouteToHandler("PUT", "/api/v1/workers/some-worker/heartbeat", func(w http.ResponseWriter, r *http.Request) {
								var worker atc.Worker
								Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())

								err := json.NewDecoder(r.Body).Decode(&worker)
								Expect(err).NotTo(HaveOccurred())

								ttl, err := time.ParseDuration(r.URL.Query().Get("ttl"))
								Expect(err).NotTo(HaveOccurred())

								heartbeated <- registration{worker, ttl}
							})

							gardenStubs := make(chan func() ([]garden.Container, error), 4)

							gardenStubs <- func() ([]garden.Container, error) {
								return []garden.Container{
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
								}, nil
							}

							gardenStubs <- func() ([]garden.Container, error) {
								return []garden.Container{
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
								}, nil
							}

							gardenStubs <- func() ([]garden.Container, error) {
								return nil, errors.New("garden was weeded")
							}

							gardenStubs <- func() ([]garden.Container, error) {
								return []garden.Container{
									new(gfakes.FakeContainer),
								}, nil
							}

							close(gardenStubs)

							fakeBackend.ContainersStub = func(garden.Properties) ([]garden.Container, error) {
								return (<-gardenStubs)()
							}

							baggageclaimServer.AppendHandlers(
								ghttp.CombineHandlers(
									ghttp.VerifyRequest("GET", "/volumes"),
									ghttp.RespondWithJSONEncoded(http.StatusOK, []baggageclaim.VolumeResponse{
										{Handle: "handle-a"},
										{Handle: "handle-b"},
									}),
								),
								ghttp.CombineHandlers(
									ghttp.VerifyRequest("GET", "/volumes"),
									ghttp.RespondWithJSONEncoded(http.StatusOK, []baggageclaim.VolumeResponse{
										{Handle: "handle-a"},
									}),
								),
								ghttp.CombineHandlers(
									ghttp.VerifyRequest("GET", "/volumes"),
									ghttp.RespondWithJSONEncoded(http.StatusOK, []baggageclaim.VolumeResponse{
										{Handle: "handle-a"},
										{Handle: "handle-b"},
										{Handle: "handle-c"},
									}),
								),
								ghttp.CombineHandlers(
									ghttp.VerifyRequest("GET", "/volumes"),
									ghttp.RespondWithJSONEncoded(http.StatusOK, []baggageclaim.VolumeResponse{}),
								),
							)

						})

						JustBeforeEach(func() {
							err := json.NewEncoder(sshStdin).Encode(workerPayload)
							Expect(err).NotTo(HaveOccurred())
						})

						It("continuously registers it with the ATC as long as it works", func() {
							expectedWorkerPayload := workerPayload

							expectedWorkerPayload.ActiveContainers = 3
							expectedWorkerPayload.ActiveVolumes = 2

							a := time.Now()
							Expect(<-registered).To(Equal(registration{
								worker: expectedWorkerPayload,
								ttl:    2 * heartbeatInterval,
							}))

							expectedWorkerPayload.ActiveContainers = 2
							expectedWorkerPayload.ActiveVolumes = 1

							b := time.Now()
							Expect(<-heartbeated).To(Equal(registration{
								worker: expectedWorkerPayload,
								ttl:    2 * heartbeatInterval,
							}))

							Expect(b.Sub(a)).To(BeNumerically("~", heartbeatInterval, 1*time.Second))

							Consistently(heartbeated, 2*heartbeatInterval).ShouldNot(Receive())

							expectedWorkerPayload.ActiveContainers = 1
							expectedWorkerPayload.ActiveVolumes = 0

							c := time.Now()
							Expect(<-heartbeated).To(Equal(registration{
								worker: expectedWorkerPayload,
								ttl:    2 * heartbeatInterval,
							}))

							Expect(c.Sub(b)).To(BeNumerically("~", 3*heartbeatInterval, 1*time.Second))

							Eventually(sshSess.Out).Should(gbytes.Say("heartbeat"))
						})
					})
				})
			})

			Context("with a valid team key", func() {
				BeforeEach(func() {
					sshArgv = append(sshArgv, "-i", teamUserKey)
				})

				Context("when running register-worker", func() {
					BeforeEach(func() {
						sshArgv = append(sshArgv, "register-worker")
					})

					It("does not exit", func() {
						Consistently(sshSess, 1).ShouldNot(gexec.Exit())
					})

					Context("sending a worker with any team payload on stdin", func() {
						type registration struct {
							worker atc.Worker
							ttl    time.Duration
						}

						var workerPayload atc.Worker
						var registered chan registration
						var heartbeated chan registration

						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",

								GardenAddr:      gardenAddr,
								BaggageclaimURL: baggageclaimServer.URL(),

								Platform: "linux",
								Tags:     []string{"some", "tags"},
								Team:     "exampleteam",

								ResourceTypes: []atc.WorkerResourceType{
									{Type: "resource-type-a", Image: "resource-image-a"},
									{Type: "resource-type-b", Image: "resource-image-b"},
								},
							}

							registered = make(chan registration)
							heartbeated = make(chan registration)

							atcServer.RouteToHandler("POST", "/api/v1/workers", func(w http.ResponseWriter, r *http.Request) {
								var worker atc.Worker
								Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())

								err := json.NewDecoder(r.Body).Decode(&worker)
								Expect(err).NotTo(HaveOccurred())

								ttl, err := time.ParseDuration(r.URL.Query().Get("ttl"))
								Expect(err).NotTo(HaveOccurred())

								registered <- registration{worker, ttl}
							})

							atcServer.RouteToHandler("PUT", "/api/v1/workers/some-worker/heartbeat", func(w http.ResponseWriter, r *http.Request) {
								var worker atc.Worker
								Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())

								err := json.NewDecoder(r.Body).Decode(&worker)
								Expect(err).NotTo(HaveOccurred())

								ttl, err := time.ParseDuration(r.URL.Query().Get("ttl"))
								Expect(err).NotTo(HaveOccurred())

								heartbeated <- registration{worker, ttl}
							})

							gardenStubs := make(chan func() ([]garden.Container, error), 4)

							gardenStubs <- func() ([]garden.Container, error) {
								return []garden.Container{
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
								}, nil
							}

							gardenStubs <- func() ([]garden.Container, error) {
								return []garden.Container{
									new(gfakes.FakeContainer),
									new(gfakes.FakeContainer),
								}, nil
							}

							gardenStubs <- func() ([]garden.Container, error) {
								return nil, errors.New("garden was weeded")
							}

							gardenStubs <- func() ([]garden.Container, error) {
								return []garden.Container{
									new(gfakes.FakeContainer),
								}, nil
							}

							close(gardenStubs)

							baggageclaimServer.AppendHandlers(
								ghttp.CombineHandlers(
									ghttp.VerifyRequest("GET", "/volumes"),
									ghttp.RespondWithJSONEncoded(http.StatusOK, []baggageclaim.VolumeResponse{
										{Handle: "handle-a"},
										{Handle: "handle-b"},
									}),
								),
								ghttp.CombineHandlers(
									ghttp.VerifyRequest("GET", "/volumes"),
									ghttp.RespondWithJSONEncoded(http.StatusOK, []baggageclaim.VolumeResponse{
										{Handle: "handle-a"},
									}),
								),
								ghttp.CombineHandlers(
									ghttp.VerifyRequest("GET", "/volumes"),
									ghttp.RespondWithJSONEncoded(http.StatusOK, []baggageclaim.VolumeResponse{
										{Handle: "handle-a"},
										{Handle: "handle-b"},
										{Handle: "handle-c"},
									}),
								),
								ghttp.CombineHandlers(
									ghttp.VerifyRequest("GET", "/volumes"),
									ghttp.RespondWithJSONEncoded(http.StatusOK, []baggageclaim.VolumeResponse{}),
								),
							)

							fakeBackend.ContainersStub = func(garden.Properties) ([]garden.Container, error) {
								return (<-gardenStubs)()
							}
						})

						JustBeforeEach(func() {
							err := json.NewEncoder(sshStdin).Encode(workerPayload)
							Expect(err).NotTo(HaveOccurred())
						})

						It("continuously registers it with the ATC as long as it works", func() {
							expectedWorkerPayload := workerPayload

							expectedWorkerPayload.ActiveContainers = 3
							expectedWorkerPayload.ActiveVolumes = 2

							a := time.Now()
							Expect(<-registered).To(Equal(registration{
								worker: expectedWorkerPayload,
								ttl:    2 * heartbeatInterval,
							}))

							expectedWorkerPayload.ActiveContainers = 2
							expectedWorkerPayload.ActiveVolumes = 1

							b := time.Now()
							Expect(<-heartbeated).To(Equal(registration{
								worker: expectedWorkerPayload,
								ttl:    2 * heartbeatInterval,
							}))

							Expect(b.Sub(a)).To(BeNumerically("~", heartbeatInterval, 1*time.Second))

							Consistently(heartbeated, 2*heartbeatInterval).ShouldNot(Receive())

							expectedWorkerPayload.ActiveContainers = 1
							expectedWorkerPayload.ActiveVolumes = 0

							c := time.Now()
							Expect(<-heartbeated).To(Equal(registration{
								worker: expectedWorkerPayload,
								ttl:    2 * heartbeatInterval,
							}))

							Expect(c.Sub(b)).To(BeNumerically("~", 3*heartbeatInterval, 1*time.Second))

							Eventually(sshSess.Out).Should(gbytes.Say("heartbeat"))
						})
					})

					Context("sending a worker from a different team", func() {
						var workerPayload atc.Worker

						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name:       "some-worker",
								GardenAddr: gardenAddr,

								Platform: "linux",
								Tags:     []string{"some", "tags"},
								Team:     "wrong",

								ResourceTypes: []atc.WorkerResourceType{
									{Type: "resource-type-a", Image: "resource-image-a"},
									{Type: "resource-type-b", Image: "resource-image-b"},
								},
							}
						})

						JustBeforeEach(func() {
							err := json.NewEncoder(sshStdin).Encode(workerPayload)
							Expect(err).NotTo(HaveOccurred())
						})

						It("should error with worker not allowed", func() {
							Eventually(tsaRunner.Buffer()).Should(gbytes.Say("worker-not-allowed-to-team"))
						})
					})
				})

				Context("when running land-worker", func() {
					var workerPayload atc.Worker

					BeforeEach(func() {
						sshArgv = append(sshArgv, "land-worker")
					})

					JustBeforeEach(func() {
						err := json.NewEncoder(sshStdin).Encode(workerPayload)
						Expect(err).NotTo(HaveOccurred())
					})

					Context("when the worker is from the same team as the user", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
								Team: "exampleteam",
							}
						})

						Context("when the ATC is working", func() {
							BeforeEach(func() {
								atcServer.AppendHandlers(ghttp.CombineHandlers(
									ghttp.VerifyRequest("PUT", "/api/v1/workers/some-worker/land"),
									http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
										Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
									}),
									ghttp.RespondWith(200, nil, nil),
								))
							})

							It("sends a request to the ATC to land the worker", func() {
								Eventually(sshSess, 3).Should(gexec.Exit(0))
								Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
							})
						})

						Context("when the ATC responds a missing worker (404)", func() {
							BeforeEach(func() {
								atcServer.AppendHandlers(ghttp.CombineHandlers(
									ghttp.VerifyRequest("PUT", "/api/v1/workers/some-worker/land"),
									http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
										Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
									}),
									ghttp.RespondWith(404, nil, nil),
								))
							})

							It("exits with failure", func() {
								Eventually(tsaRunner.Buffer()).Should(gbytes.Say("404"))
								Eventually(sshSess, 3).Should(gexec.Exit(1))
								Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
							})
						})

						Context("when the ATC responds with an error", func() {
							BeforeEach(func() {
								atcServer.AppendHandlers(ghttp.CombineHandlers(
									ghttp.VerifyRequest("PUT", "/api/v1/workers/some-worker/land"),
									http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
										Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
									}),
									ghttp.RespondWith(500, nil, nil),
								))
							})

							It("exits with failure", func() {
								Eventually(tsaRunner.Buffer()).Should(gbytes.Say("500"))
								Eventually(sshSess, 3).Should(gexec.Exit(1))
								Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
							})
						})
					})

					Context("when the worker is from a different team", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
								Team: "wrong",
							}
						})

						It("exits with failure", func() {
							Eventually(tsaRunner.Buffer()).Should(gbytes.Say("worker-not-allowed-to-team"))
							Eventually(sshSess, 3).Should(gexec.Exit(1))

							Expect(atcServer.ReceivedRequests()).To(HaveLen(0))
						})
					})

					Context("when landing a non-team worker", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
							}
						})

						It("exits with failure", func() {
							Eventually(tsaRunner.Buffer()).Should(gbytes.Say("worker-not-allowed-to-team"))
							Eventually(sshSess, 3).Should(gexec.Exit(1))

							Expect(atcServer.ReceivedRequests()).To(HaveLen(0))
						})
					})
				})

				Context("when running retire-worker", func() {
					var workerPayload atc.Worker

					BeforeEach(func() {
						sshArgv = append(sshArgv, "retire-worker")
					})

					JustBeforeEach(func() {
						err := json.NewEncoder(sshStdin).Encode(workerPayload)
						Expect(err).NotTo(HaveOccurred())
					})

					Context("when the worker is from the same team as the user", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
								Team: "exampleteam",
							}
						})

						Context("when the ATC is working", func() {
							BeforeEach(func() {
								atcServer.AppendHandlers(ghttp.CombineHandlers(
									ghttp.VerifyRequest("PUT", "/api/v1/workers/some-worker/retire"),
									http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
										Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
									}),
									ghttp.RespondWith(200, nil, nil),
								))
							})

							It("sends a request to the ATC to land the worker", func() {
								Eventually(sshSess, 3).Should(gexec.Exit(0))
								Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
							})
						})

						Context("when the ATC responds a missing worker (404)", func() {
							BeforeEach(func() {
								atcServer.AppendHandlers(ghttp.CombineHandlers(
									ghttp.VerifyRequest("PUT", "/api/v1/workers/some-worker/retire"),
									http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
										Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
									}),
									ghttp.RespondWith(404, nil, nil),
								))
							})

							It("exits with no failure", func() {
								Eventually(sshSess, 3).Should(gexec.Exit(0))
								Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
							})
						})

						Context("when the ATC responds with an error", func() {
							BeforeEach(func() {
								atcServer.AppendHandlers(ghttp.CombineHandlers(
									ghttp.VerifyRequest("PUT", "/api/v1/workers/some-worker/retire"),
									http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
										Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
									}),
									ghttp.RespondWith(500, nil, nil),
								))
							})

							It("exits with failure", func() {
								Eventually(tsaRunner.Buffer()).Should(gbytes.Say("500"))
								Eventually(sshSess, 3).Should(gexec.Exit(1))
								Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
							})
						})
					})

					Context("when the worker is from a different team", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
								Team: "wrong",
							}
						})

						It("exits with failure", func() {
							Eventually(tsaRunner.Buffer()).Should(gbytes.Say("worker-not-allowed-to-team"))
							Eventually(sshSess, 3).Should(gexec.Exit(1))

							Expect(atcServer.ReceivedRequests()).To(HaveLen(0))
						})
					})

					Context("when retiring a non-team worker", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
							}
						})

						It("exits with failure", func() {
							Eventually(tsaRunner.Buffer()).Should(gbytes.Say("worker-not-allowed-to-team"))
							Eventually(sshSess, 3).Should(gexec.Exit(1))

							Expect(atcServer.ReceivedRequests()).To(HaveLen(0))
						})
					})
				})

				Context("when running delete-worker", func() {
					var workerPayload atc.Worker

					BeforeEach(func() {
						sshArgv = append(sshArgv, "delete-worker")
					})

					JustBeforeEach(func() {
						err := json.NewEncoder(sshStdin).Encode(workerPayload)
						Expect(err).NotTo(HaveOccurred())
					})

					Context("when the worker is from the same team as the user", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
								Team: "exampleteam",
							}
						})

						Context("when the ATC is working", func() {
							BeforeEach(func() {
								atcServer.AppendHandlers(ghttp.CombineHandlers(
									ghttp.VerifyRequest("DELETE", "/api/v1/workers/some-worker"),
									http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
										Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
									}),
									ghttp.RespondWith(200, nil, nil),
								))
							})

							It("sends a request to the ATC to delete the worker", func() {
								Eventually(sshSess, 3).Should(gexec.Exit(0))
								Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
							})
						})

						Context("when the ATC responds with an error", func() {
							BeforeEach(func() {
								atcServer.AppendHandlers(ghttp.CombineHandlers(
									ghttp.VerifyRequest("DELETE", "/api/v1/workers/some-worker"),
									http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
										Expect(accessFactory.Create(r).IsAuthenticated()).To(BeTrue())
									}),
									ghttp.RespondWith(500, nil, nil),
								))
							})

							It("exits with failure", func() {
								Eventually(tsaRunner.Buffer()).Should(gbytes.Say("500"))
								Eventually(sshSess, 3).Should(gexec.Exit(1))
								Expect(atcServer.ReceivedRequests()).To(HaveLen(1))
							})
						})
					})

					Context("when the worker is from a different team", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
								Team: "wrong",
							}
						})

						It("exits with failure", func() {
							Eventually(tsaRunner.Buffer()).Should(gbytes.Say("worker-not-allowed-to-team"))
							Eventually(sshSess, 3).Should(gexec.Exit(1))

							Expect(atcServer.ReceivedRequests()).To(HaveLen(0))
						})
					})

					Context("when retiring a non-team worker", func() {
						BeforeEach(func() {
							workerPayload = atc.Worker{
								Name: "some-worker",
							}
						})

						It("exits with failure", func() {
							Eventually(tsaRunner.Buffer()).Should(gbytes.Say("worker-not-allowed-to-team"))
							Eventually(sshSess, 3).Should(gexec.Exit(1))

							Expect(atcServer.ReceivedRequests()).To(HaveLen(0))
						})
					})
				})
			})
		})
	})
})
