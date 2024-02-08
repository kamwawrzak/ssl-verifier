package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testUrlsPath = "../../test-files/test-urls.json"
)

func TestGetUrls(t *testing.T) {
	// arrange
	expected := URLs {
		"example.com:443",
		"https://google.com",
	}

	// act
	actual, err := GetUrls(testUrlsPath)

	// assert
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}