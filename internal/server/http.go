package server

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
)

type Server struct {
	port int
	router chi.Router
	handler *verifyHandler
}

func NewServer(port int, handler *verifyHandler) *Server {
	return &Server{
		port: port,
		router: chi.NewRouter(),
		handler: handler,
	}
}

func (s *Server) Start() error {
	s.registerEndpoints()
	err := http.ListenAndServe(fmt.Sprintf(":%d", s.port), s.router)
	if err != nil {
		return fmt.Errorf("failed to start server %v", err)
	}
	return nil
}

func (s *Server) registerEndpoints() {
	s.router.Post("/verify", s.handler.verifyCertificate)
}