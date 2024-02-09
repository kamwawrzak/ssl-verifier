package testhelper

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/kamwawrzak/sslverifier/internal/model"
)

func GetResultsFromFile(path string) ([]*model.Result, error){
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	
	var res []*model.Result
    err = json.Unmarshal(file, &res)
    if err != nil {
        return nil, fmt.Errorf("error during unmarshaling: %w", err)
    }

	return res, nil
}

func CleanTestFile(path string) {
	os.Remove(path)
}
