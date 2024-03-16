package server

import (
	"encoding/json"
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/kamwawrzak/sslverifier/internal/model"
)

type certVerifier interface {
	Verify(string) (*model.Result, error)
}

type verifyHandler struct {
	log *logrus.Logger
	verifier certVerifier
}

func NewVerifyHandler(log *logrus.Logger, verifier certVerifier) *verifyHandler {
	return &verifyHandler{
		log: log,
		verifier: verifier,
	}
}

type requestInput struct {
	Urls []string `json:"urls"`
}

type response struct {
	Results []*model.Result `json:"results"`
}


func (h *verifyHandler) verifyCertificate(w http.ResponseWriter, r *http.Request) {
	var input requestInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.log.WithError(err).Error("Decode JSON failed")
		http.Error(w, "Failed to decode JSON", http.StatusBadRequest)
		return
	}
	var results []*model.Result
	for _, url := range input.Urls {
		res, err := h.verifier.Verify(url)
		if err != nil {
			h.log.WithError(err).Error("Certificate verification failed")
			http.Error(w, "Unexpected error occurred", http.StatusInternalServerError)
			return
		}
		results = append(results, res)
	}
	
	resp := response{
		Results: results,
	}

	err := json.NewEncoder(w).Encode(resp)
	if err != nil {
		h.log.WithError(err).Error("Encode JSON failed")
		http.Error(w, "Unexpected error occurred", http.StatusInternalServerError)
		return
	}
}