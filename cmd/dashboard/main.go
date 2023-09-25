package main

import (
	"flag"
	"log"
)

type App struct {
	ZoneFilePath string
	TSIGSecret   string
}

func main() {

	zoneFilePath := flag.String("zone-file", "./db.example.com", "Path to Zone-file")
	secret := flag.String("secret", "s6Nd%+pPbnzHbS*+9Pk8qGWhTzbpa@ge", "TSIG key")

	flag.Parse()

	app := &App{
		ZoneFilePath: *zoneFilePath,
		TSIGSecret:   *secret,
	}

	t, err := loadTemplates()
	if err != nil {
		log.Fatal(err)
	}
	templateCache = t
	// Start Server
	app.RunServer()

}
