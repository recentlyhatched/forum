ChromeOS only (Linux - debian)
Install Docker from docker.io

Check if Docker deamon is running
`sudo systemctl status docker`
enter "q" in the terminal to quit

Start Docker daemon if not running
`sudo systemctl start docker`

1. To run with Docker
Run `sudo docker build -t forum .`

Then run `sudo docker run -p 8080:8080 -v $(pwd)/data:/data forum`

Then go to [http://penguin.linux.test:8080/](http://penguin.linux.test:8080/)

2. To compile and run with Go
Run `go run main.go`

