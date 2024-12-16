package main

import (
	"fmt"
	"path/filepath"
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
	"gioui.org/widget/material"
	"github.com/lastlogin-net/obligator"
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

	cacheDir, err := os.UserCacheDir()
	exitOnError(err)

	waygateDir := filepath.Join(cacheDir, "WaygateClientGUI")

	err = os.MkdirAll(waygateDir, os.ModePerm)
	exitOnError(err)

	stdoutFilePath := filepath.Join(waygateDir, "stdout.txt")
	stdoutFile, err := openLogFile(stdoutFilePath)
	exitOnError(err)

	stderrFilePath := filepath.Join(waygateDir, "stderr.txt")
	stderrFile, err := openLogFile(stderrFilePath)
	exitOnError(err)

	os.Stdout = stdoutFile
	os.Stderr = stderrFile

	eventCh := make(chan interface{}, 1)

	waygateConfig := &waygate.ClientConfig{
		Dir: waygateDir,
		//Public: true,
	}
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
				fmt.Println("https://" + evt.TunnelConfig.Domain)
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
	userList   *widget.List
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
		userList: &widget.List{
			List: layout.List{
				Axis: layout.Vertical,
			},
		},
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
			return material.List(p.theme, p.userList).Layout(gtx, len(users), func(gtx C, i int) D {
				return material.Label(p.theme, unit.Sp(16), users[i]).Layout(gtx)
				//return layout.UniformInset(unit.Dp(16)).Layout(gtx, widgets[i])
			})
		}),
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

func openLogFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
}

func exitOnError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
}
