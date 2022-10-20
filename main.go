// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/docker/go-plugins-helpers/authorization"
	version_pkg "github.com/open-policy-agent/opa-docker-authz/version"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/loader"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/sdk"
)

// DockerAuthZPlugin implements the authorization.Plugin interface. Every
// request received by the Docker daemon will be forwarded to the AuthZReq
// function. The AuthZReq function returns a response that indicates whether
// the request should be allowed or denied.
type DockerAuthZPlugin struct {
	configFile       string
	policyFile       string
	allowPath        string
	instanceID       string
	skipPing         bool
	quiet            bool
	logOnlyDenied    bool
	notifyServerAddr string // prdcv
	deniedLogs       []byte //prdcv
	opa              *sdk.OPA
}

// AuthZReq is called when the Docker daemon receives an API request. AuthZReq
// returns an authorization.Response that indicates whether the request should
// be allowed or denied.
func (p DockerAuthZPlugin) AuthZReq(r authorization.Request) authorization.Response {

	ctx := context.Background()

	allowed, err := p.evaluate(ctx, r)

	if allowed {
		return authorization.Response{Allow: true}
	} else if err != nil {
		return authorization.Response{Err: err.Error()}
	}

	return authorization.Response{Msg: "request rejected by administrative policy"}
}

// AuthZRes is called before the Docker daemon returns an API response. All responses
// are allowed.
func (DockerAuthZPlugin) AuthZRes(r authorization.Request) authorization.Response {

	// PRDCV implement here to print the response part inside the Request
	var body interface{}
	if r.ResponseHeaders["Content-Type"] == "application/json" && len(r.ResponseBody) > 0 {
		if err := json.Unmarshal(r.ResponseBody, &body); err != nil {
			fmt.Println("Error when parsing response in request")
		} else {
			// Care about:
			// 1. ResponseStatusCode
			// 2. ResponseBody
			// 3. ResponseHeaders
			fmt.Println("=============== Start the response body")
			output_response := map[string]interface{}{
				"ResponseHeader": r.ResponseHeaders,
				"ResponseCode":   r.ResponseStatusCode,
				"Body":           body,
			}
			op, _ := json.Marshal(output_response)
			log.Printf("%s\n", string(op))
			fmt.Println("=============== End of the response body")
		}
	} else {
		bodyString := string(r.ResponseBody)
		log.Printf(bodyString)
	}

	//
	return authorization.Response{Allow: true}
}

func (p DockerAuthZPlugin) evaluatePolicyFile(ctx context.Context, r authorization.Request) (bool, error) {

	if _, err := os.Stat(p.policyFile); os.IsNotExist(err) {
		log.Printf("OPA policy file %s does not exist, failing open and allowing request", p.policyFile)
		return true, err
	}

	bs, err := ioutil.ReadFile(p.policyFile)
	if err != nil {
		return false, err
	}

	input, err := makeInput(r)
	if err != nil {
		return false, err
	}

	allowed, err := func() (bool, error) {

		eval := rego.New(
			rego.Query(p.allowPath),
			rego.Input(input),
			rego.Module(p.policyFile, string(bs)),
		)

		rs, err := eval.Eval(ctx)
		if err != nil {
			return false, err
		}

		if len(rs) == 0 {
			// Decision is undefined. Fallback to deny.
			return false, nil
		}

		allowed, ok := rs[0].Expressions[0].Value.(bool)
		if !ok {
			return false, fmt.Errorf("administrative policy decision invalid")
		}

		return allowed, nil

	}()

	decisionID, _ := uuid4()
	configHash := sha256.Sum256(bs)
	labels := map[string]string{
		"app":            "opa-docker-authz",
		"id":             p.instanceID,
		"opa_version":    version_pkg.OPAVersion,
		"plugin_version": version_pkg.Version,
	}
	decisionLog := map[string]interface{}{
		"labels":      labels,
		"decision_id": decisionID,
		"config_hash": hex.EncodeToString(configHash[:]),
		"input":       input,
		"result":      allowed,
		"timestamp":   time.Now().Format(time.RFC3339Nano),
	}

	// PRDCV add start
	decisionLog["OPA_decision"] = allowed
	// PRDCV add end

	if err != nil {
		i, _ := json.Marshal(input)
		// PRDCV added start
		decisionLog["Error"] = err
		p.deniedLogs, _ = json.Marshal(decisionLog)
		// PRDCV add end here

		log.Printf("Returning OPA policy decision: %v (error: %v; input: %v)", allowed, err, i)
		p.sendErrorMessage()
	} else {
		if !p.quiet {
			if !(p.logOnlyDenied && allowed) {
				// PRDCV added start here
				decisionLog["Error"] = nil
				p.deniedLogs, _ = json.Marshal(decisionLog)
				dl := p.deniedLogs
				// PRDCV add end here

				// dl, _ := json.Marshal(decisionLog)
				log.Printf("Returning OPA policy decision: %v: %s", allowed, string(dl))
				p.sendErrorMessage()
			}
		}
	}

	return allowed, err
}

func (p DockerAuthZPlugin) evaluate(ctx context.Context, r authorization.Request) (bool, error) {

	if p.skipPing && r.RequestMethod == "HEAD" && r.RequestURI == "/_ping" {
		return true, nil
	}

	if p.configFile != "" {
		input, err := makeInput(r)
		if err != nil {
			return false, err
		}

		decisionOptions := sdk.DecisionOptions{
			Input: input,
			Path:  p.allowPath,
		}

		result, err := p.opa.Decision(ctx, decisionOptions)
		if err != nil {
			return false, err
		}

		decision, ok := result.Result.(bool)
		if !ok || !decision {
			return false, nil
		}
		return true, nil

	}

	return p.evaluatePolicyFile(ctx, r)
}

func makeInput(r authorization.Request) (interface{}, error) {

	var body interface{}

	if r.RequestHeaders["Content-Type"] == "application/json" && len(r.RequestBody) > 0 {
		if err := json.Unmarshal(r.RequestBody, &body); err != nil {
			return nil, err
		}
	}

	u, err := url.Parse(r.RequestURI)
	if err != nil {
		return nil, err
	}

	input := map[string]interface{}{
		"Headers":    r.RequestHeaders,
		"Path":       r.RequestURI,
		"PathPlain":  u.Path,
		"PathArr":    strings.Split(u.Path, "/"),
		"Query":      u.Query(),
		"Method":     r.RequestMethod,
		"Body":       body,
		"User":       r.User,
		"AuthMethod": r.UserAuthNMethod,
	}

	return input, nil
}

func uuid4() (string, error) {

	bs := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, bs)
	if n != len(bs) || err != nil {
		return "", err
	}
	bs[8] = bs[8]&^0xc0 | 0x80
	bs[6] = bs[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", bs[0:4], bs[4:6], bs[6:8], bs[8:10], bs[10:]), nil
}

func regoSyntax(p string) int {

	stuffs := []string{p}

	result, err := loader.AllRegos(stuffs)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return 1
	}

	modules := map[string]*ast.Module{}

	for _, m := range result.Modules {
		modules[m.Name] = m.Parsed
	}

	compiler := ast.NewCompiler().SetErrorLimit(0)

	if compiler.Compile(modules); compiler.Failed() {
		for _, err := range compiler.Errors {
			_, _ = fmt.Fprintln(os.Stderr, err)
		}
		return 1
	}

	return 0
}

func initOPA(ctx context.Context, configFile string) (*sdk.OPA, error) {

	buf, err := os.Open(configFile)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err = buf.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	options := sdk.Options{
		Config: buf,
	}

	return sdk.New(ctx, options)
}

func normalizeAllowPath(path string, useConfig bool) string {

	if useConfig && strings.HasPrefix(path, "data") {
		return strings.ReplaceAll(strings.TrimPrefix(path, "data"), ".", "/")
	}
	if !useConfig && strings.HasPrefix(path, "/") {
		return "data" + strings.ReplaceAll(strings.TrimPrefix(path, "data"), "/", ".")
	}
	return path
}

//	++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ //
//
// Add by PRDCV
// To-do: send https request
func (p DockerAuthZPlugin) sendErrorMessage() error {
	responseBody := bytes.NewBuffer(p.deniedLogs)
	//Leverage Go's HTTP Post function to make request
	resp, err := http.Post(
		p.notifyServerAddr,
		"application/json",
		responseBody,
	)
	//Handle Error
	if err != nil {
		// log.Fatalf("An Error Occured %v", err)
		log.Printf("[WARN] An Error Occured in HTTP Sever: %v", err)
		return err // exit function
	}
	defer resp.Body.Close()
	//Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// log.Fatalln(err)
		log.Printf("[WARN] %v", err)
		return err
	}
	sb := string(body)
	log.Printf(sb)
	return nil
}

func main() {

	pluginName := flag.String("plugin-name", "opa-docker-authz", "sets the plugin name that will be registered with Docker")
	allowPath := flag.String("allowPath", "data.docker.authz.allow", "sets the path of the allow decision in OPA")
	configFile := flag.String("config-file", "", "sets the path of the config file to load")
	policyFile := flag.String("policy-file", "", "sets the path of the policy file to load")
	skipPing := flag.Bool("skip-ping", true, "skip policy evaluation for requests to /_ping endpoint")
	version := flag.Bool("version", false, "print the version of the plugin")
	check := flag.Bool("check", false, "checks the syntax of the policy-file")
	quiet := flag.Bool("quiet", false, "disable logging of each HTTP request (policy-file mode)")
	logOnlyDenied := flag.Bool("log-only-denied", false, "only log denied requests (policy-file mode)")
	notifyServerAddr := flag.String("notify-server-addr", "http://localhost:8001", "sets the receive notification server from this plugin")

	flag.Parse()

	if *version {
		fmt.Println("Version:", version_pkg.Version)
		fmt.Println("OPA Version:", version_pkg.OPAVersion)
		os.Exit(0)
	}

	ctx := context.Background()
	useConfig := *configFile != ""

	var opa *sdk.OPA
	if useConfig {
		if *policyFile != "" {
			log.Fatal("Only one of config-file and policy-file arguments allowed")
		}

		var err error
		opa, err = initOPA(ctx, *configFile)
		if err != nil {
			log.Fatal(err)
		}
		defer opa.Stop(ctx)
	}

	instanceID, _ := uuid4()
	p := DockerAuthZPlugin{
		configFile:       *configFile,
		policyFile:       *policyFile,
		allowPath:        normalizeAllowPath(*allowPath, useConfig),
		instanceID:       instanceID,
		skipPing:         *skipPing,
		quiet:            *quiet,
		logOnlyDenied:    *logOnlyDenied,
		notifyServerAddr: *notifyServerAddr,
		opa:              opa,
	}

	if *check && *policyFile != "" {
		os.Exit(regoSyntax(*policyFile))
	}

	h := authorization.NewHandler(p)
	log.Println("Starting server.")
	err := h.ServeUnix(*pluginName, 0)
	if err != nil {
		log.Printf("Failed serving on socket: %v", err)
	}
}
