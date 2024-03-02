# SSL Verifier

## Run locally

### Build server and cli binaries
`make build-all`

### Running HTTP server
**On localhost**
Run ssl-verifier (port value by default is set to 8080)
`make run-server port=<optional_port_value>`

**In docker container**
Build docker image
`make build-docker`

Run docker container (port value by default is set to 8080)
`make run-docker-server port=<optional_port_value>`

**Example request**
`curl -X POST -d '{"urls": ["example.com", "https://google.com"]}' localhost:8080/verify`

### Running as CLI
* Single url
`make run-single url=<url to test>`

For instance: `make run-single url=example.com`

* Batch of urls from json file (Example json in `/examples`)

`make run-batch input=<path_to_input_file> output=<path_to_output_file>`

For instance: `make run-batch input=examples/test_urls.json output=test-results.json`
