ChromeOS only (Linux - debian)
Install Docker from docker.io

Check if Docker deamon is running
`sudo systemctl status docker`
enter "q" in the terminal to quit

Start Docker daemon if not running
`sudo systemctl start docker`

Run
`sudo docker build -t forum .`

Then run
`sudo docker run -p 8080:8080 -v $(pwd)/data:/data forum`