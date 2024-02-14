package main

import (
	"net/url"

	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/skip2/go-qrcode"
	"github.com/waygate-io/waygate-go"
)

func main() {
	a := app.New()
	w := a.NewWindow("Waygate Client")

	eventCh := make(chan interface{})

	waygateConfig := &waygate.ClientConfig{}
	waygateClient := waygate.NewClient(waygateConfig)
	waygateClient.ListenEvents(eventCh)

	oauth2Uri := ""
	var tunnelConfig waygate.TunnelConfig
	label := widget.NewLabel("Waygate Client")

	mainPage := container.NewVBox(
		widget.NewLabel("Main"),
		widget.NewButton("Connect", func() {
			go waygateClient.Run()
		}),
	)

	getTokenPage := container.NewVBox(
		widget.NewLabel("How do you want to get token?"),
		widget.NewButton("Open browser", func() {
			u, err := url.Parse(oauth2Uri)
			if err != nil {
				label.SetText(err.Error())
			}

			a.OpenURL(u)
			if err != nil {
				label.SetText(err.Error())
			}
		}),
		widget.NewButton("Show QR", func() {
			qr, err := qrcode.New(oauth2Uri, qrcode.Medium)
			if err != nil {
				label.SetText(err.Error())
			}

			img := canvas.NewImageFromImage(qr.Image(256))
			img.FillMode = canvas.ImageFillOriginal

			w.SetContent(img)
		}),
	)

	domainLabel := widget.NewLabel("Domain")
	addrEntry := widget.NewEntry()
	connectedPage := container.NewVBox(
		widget.NewLabel("Connected"),
		domainLabel,
		widget.NewLabel("Update Proxy Address:"),
		addrEntry,
		widget.NewButton("Update", func() {
			waygateClient.Proxy(tunnelConfig.Domain, addrEntry.Text)
		}),
		widget.NewButton("Disconnect", func() {
		}),
	)

	w.SetContent(mainPage)
	//w.SetContent(connectedPage)

	go func() {
		for {
			event := <-eventCh

			switch evt := event.(type) {
			case waygate.OAuth2AuthUriEvent:
				oauth2Uri = evt.Uri
				w.SetContent(getTokenPage)
			case waygate.TunnelConnectedEvent:
				tunnelConfig = evt.TunnelConfig
				domainLabel.SetText(tunnelConfig.Domain)
				w.SetContent(connectedPage)
			}
		}
	}()

	w.ShowAndRun()
}
