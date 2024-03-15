package server

import (
	"fmt"
	"net/http"
)

type Server struct {
	port int
	mux *http.ServeMux
	handler *verifyHandler
}

func NewServer(port int, handler *verifyHandler) *Server {
	return &Server{
		port: port,
		mux: http.NewServeMux(),
		handler: handler,
	}
}

func (s *Server) Start() error {
	s.registerEndpoints()
	err := http.ListenAndServe(fmt.Sprintf(":%d", s.port), s.mux)
	if err != nil {
		return fmt.Errorf("failed to start server %v", err)
	}
	return nil
}

func (s *Server) registerEndpoints() {
	s.mux.HandleFunc("POST /verify", s.handler.verifyCertificate)
}