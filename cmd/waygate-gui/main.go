package main

import (
	"fmt"
	//"image/color"
	"image/color"
	"log"
	"os"

	"gioui.org/app"
	"gioui.org/io/event"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget"
	//"gioui.org/text"
	"gioui.org/widget/material"
	"github.com/lastlogin-io/obligator"
	"github.com/pkg/browser"
	"github.com/waygate-io/waygate-go"
)

type (
	C = layout.Context
	D = layout.Dimensions
)

const (
	stateStart = iota
	stateConnected
)

func main() {
	go func() {
		w := app.NewWindow()
		err := run(w)
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}()
	app.Main()
}

func run(w *app.Window) error {

	eventCh := make(chan interface{}, 1)

	waygateConfig := &waygate.ClientConfig{}
	waygateClient := waygate.NewClient(waygateConfig)
	waygateClient.ListenEvents(eventCh)

	gioEvents := make(chan event.Event)
	acks := make(chan struct{})

	go func() {
		for {
			ev := w.NextEvent()
			gioEvents <- ev
			<-acks
			if _, ok := ev.(app.DestroyEvent); ok {
				return
			}
		}
	}()

	th := material.NewTheme()
	startPage := NewStartPage(eventCh, th)
	connectedPage := NewConnectedPage(eventCh, th)
	connected := false

	state := stateStart

	users := []string{}

	var ops op.Ops
	for {
		select {
		case e := <-eventCh:
			switch evt := e.(type) {
			case connectBtnEvent:
				if !connected {
					connected = true
					go func() {
						err := waygateClient.Run()
						if err != nil {
							fmt.Println(err)
						}
					}()
				}
			case addUserEvent:
				if evt.user != "" {
					fmt.Println("add user", evt.user)
					waygateClient.AddUser(obligator.User{
						Email: evt.user,
					})
				}
			case waygate.OAuth2AuthUriEvent:
				go func() {
					browser.OpenURL(evt.Uri)
				}()
			case waygate.TunnelConnectedEvent:
				state = stateConnected
				w.Invalidate()
				//tunnelConfig = evt.TunnelConfig
				//domainLabel.SetText(tunnelConfig.Domain)
				//w.SetContent(connectedPage)
			case waygate.UsersUpdatedEvent:
				users = []string{}
				for _, user := range evt.Users {
					users = append(users, user.Email)
				}

				w.Invalidate()
			}

		case e := <-gioEvents:
			switch e := e.(type) {
			case app.DestroyEvent:
				return e.Err
			case app.FrameEvent:
				gtx := app.NewContext(&ops, e)

				switch state {
				case stateStart:
					startPage.Layout(gtx)
				case stateConnected:
					connectedPage.Layout(gtx, users)
				}

				e.Frame(gtx.Ops)
			}

			acks <- struct{}{}
		}
	}
}

type startPage struct {
	connectBtn *widget.Clickable
	theme      *material.Theme
	events     chan interface{}
}

func NewStartPage(events chan interface{}, th *material.Theme) *startPage {
	return &startPage{
		connectBtn: new(widget.Clickable),
		theme:      th,
		events:     events,
	}
}

type connectBtnEvent struct{}

func (p *startPage) Layout(gtx C) D {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx C) D {
			for p.connectBtn.Clicked(gtx) {
				p.events <- connectBtnEvent{}
			}
			return material.Button(p.theme, p.connectBtn, "Connect").Layout(gtx)
		}),
	)
}

type connectedPage struct {
	theme      *material.Theme
	events     chan interface{}
	user       string
	userText   *widget.Editor
	addUserBtn *widget.Clickable
}

func NewConnectedPage(events chan interface{}, th *material.Theme) *connectedPage {
	return &connectedPage{
		theme:  th,
		events: events,
		userText: &widget.Editor{
			SingleLine: true,
			//Alignment:  text.End,
		},
		addUserBtn: new(widget.Clickable),
	}
}

type addUserEvent struct {
	user string
}

func (p *connectedPage) Layout(gtx C, users []string) D {
	border := widget.Border{Color: color.NRGBA{A: 0xff}, CornerRadius: unit.Dp(8), Width: unit.Dp(2)}
	inset := layout.UniformInset(unit.Dp(4))
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx C) D {
			return border.Layout(gtx, func(gtx C) D {
				return inset.Layout(gtx, material.Editor(p.theme, p.userText, "User").Layout)
			})
		}),
		layout.Rigid(func(gtx C) D {
			for p.addUserBtn.Clicked(gtx) {
				p.events <- addUserEvent{
					user: p.userText.Text(),
				}
			}
			return material.Button(p.theme, p.addUserBtn, "Add User").Layout(gtx)
		}),
	)
}

//func main() {
//	a := app.New()
//	w := a.NewWindow("Waygate Client")
//
//	eventCh := make(chan interface{})
//
//	waygateConfig := &waygate.ClientConfig{}
//	waygateClient := waygate.NewClient(waygateConfig)
//	waygateClient.ListenEvents(eventCh)
//
//	oauth2Uri := ""
//	var tunnelConfig waygate.TunnelConfig
//	label := widget.NewLabel("Waygate Client")
//
//	mainPage := container.NewVBox(
//		widget.NewLabel("Main"),
//		widget.NewButton("Connect", func() {
//			go func() {
//				err := waygateClient.Run()
//				if err != nil {
//					fmt.Println(err)
//				}
//			}()
//		}),
//	)
//
//	getTokenPage := container.NewVBox(
//		widget.NewLabel("How do you want to get token?"),
//		widget.NewButton("Open browser", func() {
//			u, err := url.Parse(oauth2Uri)
//			if err != nil {
//				label.SetText(err.Error())
//			}
//
//			a.OpenURL(u)
//			if err != nil {
//				label.SetText(err.Error())
//			}
//		}),
//		//widget.NewButton("Show QR", func() {
//		//	qr, err := qrcode.New(oauth2Uri, qrcode.Medium)
//		//	if err != nil {
//		//		label.SetText(err.Error())
//		//	}
//
//		//	img := canvas.NewImageFromImage(qr.Image(256))
//		//	img.FillMode = canvas.ImageFillOriginal
//
//		//	w.SetContent(img)
//		//}),
//	)
//
//	domainLabel := widget.NewLabel("Domain")
//	//addrEntry := widget.NewEntry()
//	userEntry := widget.NewEntry()
//	userList := container.NewVBox()
//	connectedPage := container.NewVBox(
//		widget.NewLabel("Connected"),
//		domainLabel,
//		//widget.NewLabel("Update Proxy Address:"),
//		//addrEntry,
//		//widget.NewButton("Update", func() {
//		//	waygateClient.Proxy(tunnelConfig.Domain, addrEntry.Text)
//		//}),
//		widget.NewLabel("Users:"),
//		userList,
//		userEntry,
//		widget.NewButton("Add User", func() {
//			waygateClient.AddUser(obligator.User{
//				Email: userEntry.Text,
//			})
//		}),
//		widget.NewButton("Disconnect", func() {
//		}),
//	)
//
//	w.SetContent(mainPage)
//	//w.SetContent(connectedPage)
//
//	go func() {
//		for {
//			event := <-eventCh
//
//			switch evt := event.(type) {
//			case waygate.OAuth2AuthUriEvent:
//				oauth2Uri = evt.Uri
//				w.SetContent(getTokenPage)
//			case waygate.TunnelConnectedEvent:
//				tunnelConfig = evt.TunnelConfig
//				domainLabel.SetText(tunnelConfig.Domain)
//				w.SetContent(connectedPage)
//
//			case waygate.UsersUpdatedEvent:
//
//				userList.RemoveAll()
//
//				for _, user := range evt.Users {
//					userList.Add(widget.NewLabel(user.Email))
//				}
//			}
//		}
//	}()
//
//	w.ShowAndRun()
//}
