package beacon_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"syscall"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/garden/gardenfakes"
	"code.cloudfoundry.org/lager"
	"github.com/concourse/atc"
	"github.com/concourse/baggageclaim/volume"
	. "github.com/concourse/worker/beacon"
	"github.com/concourse/worker/beacon/beaconfakes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

var _ = Describe("Beacon", func() {

	var (
		beacon        Beacon
		fakeClient    *beaconfakes.FakeClient
		fakeSession   *beaconfakes.FakeSession
		fakeCloseable *beaconfakes.FakeCloseable
	)

	BeforeEach(func() {
		fakeClient = new(beaconfakes.FakeClient)
		fakeSession = new(beaconfakes.FakeSession)
		fakeCloseable = new(beaconfakes.FakeCloseable)
		fakeClient.NewSessionReturns(fakeSession, nil)
		fakeClient.DialReturns(fakeCloseable, nil)
		logger := lager.NewLogger("test")
		logger.RegisterSink(lager.NewWriterSink(GinkgoWriter, lager.DEBUG))

		beacon = Beacon{
			KeepAlive: true,
			Logger:    logger,
			Client:    fakeClient,
			Worker: atc.Worker{
				GardenAddr:      "1.2.3.4:7777",
				BaggageclaimURL: "wat://5.6.7.8:7788",
			},
		}
	})

	var _ = Describe("Register", func() {
		var (
			signals chan os.Signal
			ready   chan<- struct{}
		)

		BeforeEach(func() {
			signals = make(chan os.Signal, 1)
			ready = make(chan struct{}, 1)
		})

		AfterEach(func() {
			Expect(fakeCloseable.CloseCallCount()).To(Equal(1))
		})

		Context("when the exit channel takes time to exit", func() {
			var (
				keepAliveErr    chan error
				cancelKeepAlive chan struct{}
				wait            chan bool
				registerErr     chan error
			)

			JustBeforeEach(func() {
				go func() {
					registerErr <- beacon.Register(signals, make(chan struct{}, 1))
					close(registerErr)
				}()
			})

			BeforeEach(func() {
				registerErr = make(chan error, 1)
				keepAliveErr = make(chan error, 1)
				cancelKeepAlive = make(chan struct{}, 1)
				wait = make(chan bool, 1)

				fakeSession.WaitStub = func() error {
					<-wait
					signals <- syscall.SIGKILL
					return errors.New("bad-err")
				}

				fakeClient.KeepAliveReturns(keepAliveErr, cancelKeepAlive)
			})

			It("closes the session and waits for it to shut down", func() {
				Consistently(registerErr).ShouldNot(BeClosed()) // should be blocking on exit channel
				go func() {
					wait <- false
				}()
				Eventually(registerErr).Should(BeClosed()) // should stop blocking
				Expect(fakeSession.CloseCallCount()).To(Equal(2))
			})

			Context("when the runner recieves a signal", func() {
				BeforeEach(func() {
					fakeSession.WaitStub = func() error {
						<-wait
						return nil
					}
				})

				It("stops the keepalive", func() {
					go func() {
						signals <- syscall.SIGKILL
						wait <- false
					}()
					Eventually(registerErr).Should(BeClosed())
					Eventually(cancelKeepAlive).Should(BeClosed())
				})
			})

			Context("when keeping the connection alive errors", func() {
				var (
					keepAliveErr    chan error
					err             = errors.New("keepalive fail")
					cancelKeepAlive chan<- struct{}
				)

				BeforeEach(func() {
					wait := make(chan bool, 1)
					fakeSession.WaitStub = func() error {
						<-wait
						return nil
					}

					keepAliveErr = make(chan error, 1)
					cancelKeepAlive = make(chan struct{}, 1)

					fakeClient.KeepAliveReturns(keepAliveErr, cancelKeepAlive)
					go func() {
						keepAliveErr <- err
					}()
				})

				It("returns the error", func() {
					Eventually(registerErr).Should(Receive(&err))
				})
			})

		})

		Context("when exiting immediately", func() {

			var registerErr error

			JustBeforeEach(func() {
				registerErr = beacon.Register(signals, ready)
			})

			Context("when waiting on the session errors", func() {
				BeforeEach(func() {
					fakeSession.WaitReturns(errors.New("fail"))
				})
				It("returns the error", func() {
					Expect(registerErr).To(Equal(errors.New("fail")))
				})
			})

			// Context("when the registration mode is 'forward'", func() {
			// 	BeforeEach(func() {
			// 		beacon.RegistrationMode = Forward
			// 	})

			// 	It("Forwards the worker's Garden and Baggageclaim to TSA", func() {
			// 		By("using the forward-worker command")
			// 		Expect(fakeSession.StartCallCount()).To(Equal(1))
			// 		Expect(fakeSession.StartArgsForCall(0)).To(Equal("forward-worker --garden 0.0.0.0:7777 --baggageclaim 0.0.0.0:7788"))
			// 	})
			// })

			// Context("when the registration mode is 'direct'", func() {
			// 	BeforeEach(func() {
			// 		beacon.RegistrationMode = Direct
			// 	})

			// 	It("Registers directly with the TSA", func() {
			// 		By("using the register-worker command")
			// 		Expect(fakeSession.StartCallCount()).To(Equal(1))
			// 		Expect(fakeSession.StartArgsForCall(0)).To(Equal("register-worker"))
			// 	})
			// })

			// It("Forwards the worker's Garden and Baggageclaim to TSA by default", func() {
			// 	By("using the forward-worker command")
			// 	Expect(fakeSession.StartCallCount()).To(Equal(1))
			// 	Expect(fakeSession.StartArgsForCall(0)).To(Equal("forward-worker --garden 0.0.0.0:7777 --baggageclaim 0.0.0.0:7788"))
			// })

			It("sets up a proxy for the Garden server using the correct host", func() {
				Expect(fakeClient.ProxyCallCount()).To(Equal(2))
				_, proxyTo := fakeClient.ProxyArgsForCall(0)
				Expect(proxyTo).To(Equal("1.2.3.4:7777"))

				_, proxyTo = fakeClient.ProxyArgsForCall(1)
				Expect(proxyTo).To(Equal("5.6.7.8:7788"))

			})
		})
	})

	var _ = Describe("Retire", func() {
		var (
			signals   chan os.Signal
			retireErr chan error

			wait chan bool
		)

		JustBeforeEach(func() {
			signals = make(chan os.Signal)
			retireErr = make(chan error)
			wait = make(chan bool, 1)
			go func() {
				retireErr <- beacon.RetireWorker(signals, make(chan struct{}, 1))
				close(retireErr)
			}()
		})

		AfterEach(func() {
			Eventually(retireErr).Should(BeClosed())
			Expect(fakeCloseable.CloseCallCount()).To(Equal(1))
		})

		Context("when the exit channel takes time to exit", func() {
			var (
				keepAliveErr    chan error
				cancelKeepAlive chan struct{}
			)

			BeforeEach(func() {
				keepAliveErr = make(chan error, 1)
				cancelKeepAlive = make(chan struct{}, 1)

				fakeSession.WaitStub = func() error {
					<-wait
					return nil
				}

				fakeClient.KeepAliveReturns(keepAliveErr, cancelKeepAlive)
			})

			It("closes the session and waits for it to shut down", func() {
				go func() {
					signals <- syscall.SIGKILL
				}()
				Consistently(retireErr).ShouldNot(Receive()) // should be blocking on exit channel
				go func() {
					wait <- false
				}()
				Eventually(retireErr).Should(Receive()) // should stop blocking
				Expect(fakeSession.CloseCallCount()).To(Equal(2))
			})
		})
		Context("when exiting immediately", func() {

			Context("when waiting on the session errors", func() {
				err := errors.New("fail")
				BeforeEach(func() {
					fakeSession.WaitReturns(err)
				})
				It("returns the error", func() {
					Eventually(retireErr).Should(Receive(&err))
				})
			})

			Context("when the runner recieves a signal", func() {
				var (
					keepAliveErr    chan error
					cancelKeepAlive chan struct{}
				)
				BeforeEach(func() {
					keepAliveErr = make(chan error, 1)
					cancelKeepAlive = make(chan struct{}, 1)

					fakeSession.WaitStub = func() error {
						<-wait
						return nil
					}

					fakeClient.KeepAliveReturns(keepAliveErr, cancelKeepAlive)

				})

				It("stops the keepalive", func() {
					go func() {
						signals <- syscall.SIGKILL
						wait <- false
					}()
					Eventually(cancelKeepAlive).Should(BeClosed())
				})
			})

			Context("when keeping the connection alive errors", func() {
				var (
					keepAliveErr    chan error
					err             = errors.New("keepalive fail")
					cancelKeepAlive chan<- struct{}
				)

				BeforeEach(func() {
					wait := make(chan bool, 1)
					fakeSession.WaitStub = func() error {
						<-wait
						return nil
					}

					keepAliveErr = make(chan error, 1)
					cancelKeepAlive = make(chan struct{}, 1)

					fakeClient.KeepAliveReturns(keepAliveErr, cancelKeepAlive)
					go func() {
						keepAliveErr <- err
					}()
				})

				It("returns the error", func() {
					Eventually(retireErr).Should(Receive(&err))
				})
			})

			It("sets up a proxy for the Garden server using the correct host", func() {
				Eventually(retireErr).Should(BeClosed())
				Expect(fakeClient.ProxyCallCount()).To(Equal(2))
				_, proxyTo := fakeClient.ProxyArgsForCall(0)
				Expect(proxyTo).To(Equal("1.2.3.4:7777"))

				_, proxyTo = fakeClient.ProxyArgsForCall(1)
				Expect(proxyTo).To(Equal("5.6.7.8:7788"))
			})
		})
	})

	var _ = Describe("Land", func() {
		var (
			signals chan os.Signal
		)

		BeforeEach(func() {
			signals = make(chan os.Signal)
		})

		AfterEach(func() {
			Expect(fakeCloseable.CloseCallCount()).To(Equal(1))
		})

		Context("when waiting on the remote command takes some time", func() {
			var (
				keepAliveErr    chan error
				cancelKeepAlive chan struct{}
				wait            chan bool
				landErr         chan error
			)

			JustBeforeEach(func() {
				go func() {
					landErr <- beacon.LandWorker(signals, make(chan struct{}, 1))
					close(landErr)
				}()
			})

			BeforeEach(func() {
				keepAliveErr = make(chan error, 1)
				cancelKeepAlive = make(chan struct{}, 1)
				wait = make(chan bool, 1)
				landErr = make(chan error)

				fakeSession.WaitStub = func() error {
					<-wait
					return nil
				}

				fakeClient.KeepAliveReturns(keepAliveErr, cancelKeepAlive)
			})

			It("closes the session and waits for it to shut down", func() {
				Consistently(landErr).ShouldNot(BeClosed()) // should be blocking on exit channel

				go func() {
					wait <- false
				}()

				Eventually(landErr).Should(Receive()) // should stop blocking
				Expect(fakeSession.CloseCallCount()).To(Equal(1))
			})

			Context("when the runner recieves a signal", func() {
				BeforeEach(func() {
					go func() {
						signals <- syscall.SIGKILL
					}()
				})

				It("stops the keepalive", func() {
					Eventually(cancelKeepAlive).Should(BeClosed())
					go func() {
						wait <- false
					}()

					Eventually(landErr).Should(BeClosed())
				})
			})

			Context("when keeping the connection alive errors", func() {
				var (
					err = errors.New("keepalive fail")
				)

				BeforeEach(func() {
					fakeClient.KeepAliveReturns(keepAliveErr, cancelKeepAlive)
					go func() {
						keepAliveErr <- err
					}()
				})

				It("returns the error", func() {
					Eventually(landErr).Should(Receive(&err))
				})
			})

		})

		Context("when exiting immediately", func() {
			var landErr error
			JustBeforeEach(func() {
				landErr = beacon.LandWorker(signals, make(chan struct{}, 1))
			})

			Context("when waiting on the session errors", func() {
				err := errors.New("fail")
				BeforeEach(func() {
					fakeSession.WaitReturns(err)
				})
				It("returns the error", func() {
					Expect(landErr).To(Equal(err))
				})
			})

			It("sets up a proxy for the Garden server using the correct host", func() {
				Expect(fakeClient.ProxyCallCount()).To(Equal(2))
				_, proxyTo := fakeClient.ProxyArgsForCall(0)
				Expect(proxyTo).To(Equal("1.2.3.4:7777"))

				_, proxyTo = fakeClient.ProxyArgsForCall(1)
				Expect(proxyTo).To(Equal("5.6.7.8:7788"))
			})
		})
	})

	var _ = Describe("ReportVolumes", func() {
		var (
			err                error
			baggageclaimServer *ghttp.Server
		)

		BeforeEach(func() {
			baggageclaimServer = ghttp.NewServer()
			beacon.BaggageclaimAddr = baggageclaimServer.URL()
			baggageclaimServer.Reset()
		})

		AfterEach(func() {
			baggageclaimServer.Close()
		})

		JustBeforeEach(func() {
			err = beacon.ReportVolumes()
		})

		Context("when listing the volumes returns error", func() {
			BeforeEach(func() {
				baggageclaimServer.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", "/volumes"),
						ghttp.RespondWith(http.StatusFailedDependency, nil),
					),
				)
			})

			It("returns the error", func() {
				Expect(err).To(HaveOccurred())
			})

			It("does not connect to the TSA", func() {
				Expect(fakeClient.DialCallCount()).To(Equal(0))
			})
		})

		Context("when a list of volumes to report is returned", func() {
			BeforeEach(func() {
				baggageclaimServer.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("GET", "/volumes"),
						ghttp.RespondWithJSONEncoded(http.StatusOK, []volume.Volume{
							{
								Handle: "handle1",
							},
							{
								Handle: "handle2",
							},
						}),
					),
				)
			})

			It("reports the containers via the TSA", func() {
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeSession.OutputCallCount()).To(Equal(1))
				command := fakeSession.OutputArgsForCall(0)
				Expect(command).To(Equal("report-volumes handle1 handle2"))
			})
		})
	})

	var _ = Describe("ReportContainers", func() {
		var (
			err          error
			reaperServer *ghttp.Server
			gardenClient *gardenfakes.FakeClient
		)

		BeforeEach(func() {
			gardenClient = new(gardenfakes.FakeClient)
			reaperServer = ghttp.NewServer()
			reaperServer.Reset()
		})

		AfterEach(func() {
			reaperServer.Close()
		})

		JustBeforeEach(func() {
			err = beacon.ReportContainers(gardenClient)
		})

		Context("when listing the containers fails", func() {
			BeforeEach(func() {
				gardenClient.ContainersReturns(nil, errors.New("failure"))
			})

			It("returns the error", func() {
				Expect(err).To(Equal(errors.New("failure")))
			})

			It("does not connect to the TSA", func() {
				Expect(fakeClient.DialCallCount()).To(Equal(0))
			})
		})

		Context("when a list of containers to report is returned", func() {
			BeforeEach(func() {
				container1 := &gardenfakes.FakeContainer{}
				container1.HandleReturns("handle1")
				container2 := &gardenfakes.FakeContainer{}
				container2.HandleReturns("handle2")
				containers := []garden.Container{container1, container2}

				gardenClient.ContainersReturns(containers, nil)
			})

			It("reports the containers via the TSA", func() {
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeSession.OutputCallCount()).To(Equal(1))
				command := fakeSession.OutputArgsForCall(0)
				Expect(command).To(Equal("report-containers handle1 handle2"))
			})
		})
	})

	var _ = Describe("SweepContainers", func() {
		var (
			err          error
			gardenClient *gardenfakes.FakeClient
		)

		BeforeEach(func() {
			gardenClient = new(gardenfakes.FakeClient)
		})

		JustBeforeEach(func() {
			err = beacon.SweepContainers(gardenClient)
		})

		It("closes the connection to the TSA", func() {
			Expect(fakeCloseable.CloseCallCount()).To(Equal(1))
		})

		Context("when session returns error", func() {
			BeforeEach(func() {
				fakeSession.OutputReturns(nil, errors.New("fail"))
			})
			It("returns the error", func() {
				Expect(err).To(HaveOccurred())
			})
		})

		Context("when malformed json is returned", func() {
			BeforeEach(func() {
				fakeSession.OutputStub = func(cmd string) ([]byte, error) {
					return []byte("bad-json"), nil
				}
			})

			It("returns the error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("invalid character"))
			})
		})

		Context("when a list of containers to destroy is returned", func() {
			BeforeEach(func() {
				handles := []string{"handle1", "handle2"}
				handleBytes, err := json.Marshal(handles)
				Expect(err).NotTo(HaveOccurred())
				fakeSession.OutputReturns(handleBytes, nil)
			})

			It("garbage collects the containers", func() {
				Expect(gardenClient.DestroyCallCount()).To(Equal(2))
				Expect(fakeSession.OutputCallCount()).To(Equal(1))
			})
		})
	})

	var _ = Describe("SweepVolumes", func() {
		var (
			err                error
			baggageclaimServer *ghttp.Server
		)

		BeforeEach(func() {
			baggageclaimServer = ghttp.NewServer()
			beacon.BaggageclaimAddr = baggageclaimServer.URL()
			baggageclaimServer.Reset()
		})

		AfterEach(func() {
			baggageclaimServer.Close()
		})

		JustBeforeEach(func() {
			err = beacon.SweepVolumes()
		})

		It("closes the connection to the TSA", func() {
			Expect(fakeCloseable.CloseCallCount()).To(Equal(1))
		})

		Context("when session returns error", func() {
			BeforeEach(func() {
				fakeSession.OutputReturns(nil, errors.New("fail"))
			})
			It("returns the error", func() {
				Expect(err).To(HaveOccurred())
			})
		})

		Context("when malformed json is returned", func() {
			BeforeEach(func() {
				fakeSession.OutputStub = func(cmd string) ([]byte, error) {
					return []byte("bad-json"), nil
				}
			})

			It("returns the error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("invalid character"))
			})
		})

		Context("when a list of volumes to destroy is returned", func() {
			BeforeEach(func() {
				handles := []string{"handle1", "handle2"}
				handleBytes, err := json.Marshal(handles)
				Expect(err).NotTo(HaveOccurred())

				fakeSession.OutputReturns(handleBytes, nil)
				baggageclaimServer.AppendHandlers(
					ghttp.CombineHandlers(
						ghttp.VerifyRequest("DELETE", "/volumes/destroy"),
						ghttp.VerifyJSON(string(handleBytes)),
						ghttp.RespondWith(http.StatusNoContent, nil),
					),
				)
			})

			It("garbage collects the volumes", func() {
				Expect(err).NotTo(HaveOccurred())
				Expect(fakeSession.OutputCallCount()).To(Equal(1))
			})
		})
	})
})
