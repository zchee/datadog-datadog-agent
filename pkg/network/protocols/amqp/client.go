// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package amqp provides a simple wrapper around 3rd party amqp client.
package amqp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/streadway/amqp"
)

// Options is a struct to hold the options for the amqp client
type Options struct {
	ServerAddress string
	Username      string
	Password      string
	Dialer        *net.Dialer

	// WithTLS indicates whether the connection should be made using TLS
	WithTLS bool
	// TlsDialFn is a function that returns a TLS connection as an
	// io.ReadWriteCloser, suitable to be used with amqp.Open.
	TLSDialFn func() (io.ReadWriteCloser, error)
}

// Client is a wrapper around the amqp client
type Client struct {
	opts           Options
	PublishConn    *amqp.Connection
	PublishChannel *amqp.Channel
	ConsumeConn    *amqp.Connection
	ConsumeChannel *amqp.Channel
}

// NewClient creates a new amqp client
func NewClient(opts Options) (*Client, error) {
	if opts.Username == "" {
		opts.Username = User
	}

	if opts.Password == "" {
		opts.Password = Pass
	}

	publishConn, err := newAMQPConnection(opts)
	if err != nil {
		return nil, err
	}
	publishCh, err := publishConn.Channel()
	if err != nil {
		return nil, err
	}
	consumeConn, err := newAMQPConnection(opts)
	if err != nil {
		return nil, err
	}
	consumeCh, err := consumeConn.Channel()
	if err != nil {
		return nil, err
	}
	return &Client{
		opts:           opts,
		PublishConn:    publishConn,
		PublishChannel: publishCh,
		ConsumeConn:    consumeConn,
		ConsumeChannel: consumeCh,
	}, nil
}

// Queue represents an amqp queue
type Queue struct {
	Name string
}

// DeleteQueues deletes all queues from the server
func (c *Client) DeleteQueues() error {
	host, _, _ := net.SplitHostPort(c.opts.ServerAddress)
	manager := fmt.Sprintf("http://%s:15672/api/queues/", host)
	client := &http.Client{}
	req, err := http.NewRequest("GET", manager, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.opts.Username, c.opts.Password)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	queues := make([]Queue, 0)
	if err := json.NewDecoder(resp.Body).Decode(&queues); err != nil {
		return err
	}

	for _, queue := range queues {
		_, _ = c.PublishChannel.QueueDelete(queue.Name, false, false, false)
	}

	return nil
}

// Terminate closes all connections and channels
func (c *Client) Terminate() {
	c.PublishChannel.Close()
	c.ConsumeChannel.Close()
	c.PublishConn.Close()
	c.ConsumeConn.Close()
}

// DeclareQueue creates a queue with the given name
func (c *Client) DeclareQueue(name string, ch *amqp.Channel) error {
	_, err := ch.QueueDeclare(
		name,  // name
		false, // durable
		false, // delete when unused
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)
	return err
}

// Publish sends a message to the queue
func (c *Client) Publish(queue, body string) error {
	return c.PublishChannel.Publish(
		"",    // exchange
		queue, // routing key
		false, // mandatory
		false, // immediate
		amqp.Publishing{
			ContentType: "text/plain",
			Body:        []byte(body),
		})
}

// Consume reads a message from the queue
func (c *Client) Consume(queue string, numberOfMessages int) ([]string, error) {
	msgs, err := c.ConsumeChannel.Consume(
		queue,
		"",    // consumer
		true,  // auto-ack
		false, // exclusive
		false, // no-local
		false, // no-wait
		nil,   // args
	)

	if err != nil {
		return nil, err
	}

	res := make([]string, 0, numberOfMessages)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for msg := range msgs {
			res = append(res, string(msg.Body))
			if len(res) == numberOfMessages {
				return
			}
		}
	}()

	wg.Wait()

	return res, nil
}

// newAMQPConnection wraps connection creation from the "amqp" package. It handles
// the differences in the connection creation process between plaintext & TLS
// connections. Specifically, for TLS connections, it uses a
// TransparentUnixProxyServer to handle the TLS part, allowing tests to hook it
// using USM's GoTLS decoding.
// Returns a new connection to the AMQP server, on an error if it failed to
// make one.
func newAMQPConnection(opts Options) (*amqp.Connection, error) {
	url := getURL(opts)

	if opts.WithTLS {
		if opts.TLSDialFn == nil {
			return nil, errors.New("TLS dial function not set")
		}

		conn, err := opts.TLSDialFn()
		if err != nil {
			return nil, err
		}

		return amqp.Open(conn, amqp.Config{
			SASL: []amqp.Authentication{&amqp.PlainAuth{
				Username: opts.Username,
				Password: opts.Password,
			}},
			Vhost: "/",
		})
	}

	dialOptions := amqp.Config{}
	if opts.Dialer != nil {
		dialOptions.Dial = opts.Dialer.Dial
	}

	return amqp.DialConfig(url, dialOptions)
}

// getURL returns the URL to connect to the AMQP server.
func getURL(opts Options) string {
	scheme := "amqp"
	if opts.WithTLS {
		scheme = "amqps"
	}

	return fmt.Sprintf("%s://%s:%s@%s/", scheme, opts.Username, opts.Password, opts.ServerAddress)
}
