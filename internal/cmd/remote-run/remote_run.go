package remote_run

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"golang.org/x/term"

	"code-intelligence.com/cifuzz/internal/access_tokens"
	"code-intelligence.com/cifuzz/internal/bundler"
	"code-intelligence.com/cifuzz/internal/cmd/remote-run/progress"
	"code-intelligence.com/cifuzz/internal/completion"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/cmdutils"
	"code-intelligence.com/cifuzz/pkg/dialog"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/stringutil"
)

var FeaturedProjectsOrganization = "organizations/1"

type artifact struct {
	DisplayName  string `json:"display-name"`
	ResourceName string `json:"resource-name"`
}

type remoteRunOpts struct {
	bundler.Opts `mapstructure:",squash"`
	ProjectName  string `mapstructure:"project"`
	Server       string `mapstructure:"server"`
}

func (opts *remoteRunOpts) Validate() error {
	if opts.BuildSystem != config.BuildSystemCMake {
		err := errors.New("'cifuzz run remote' currently only supports CMake projects")
		log.Error(err)
		return cmdutils.WrapSilentError(err)
	}

	return opts.Opts.Validate()
}

type runRemoteCmd struct {
	opts *remoteRunOpts
}

func New() *cobra.Command {
	return newWithOptions(&remoteRunOpts{})
}

func newWithOptions(opts *remoteRunOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remote-run [flags] [<fuzz test>]...",
		Short: "Build fuzz tests and run them on a remote fuzzing server",
		Long: `This command builds fuzz tests, bundles all runtime artifacts into a
self-contained archive and uploads that to a remote fuzzing server to
start a remote fuzzing run.`,
		ValidArgsFunction: completion.ValidFuzzTests,
		Args:              cobra.ArbitraryArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Bind viper keys to flags. We can't do this in the New
			// function, because that would re-bind viper keys which
			// were bound to the flags of other commands before.
			cmdutils.ViperMustBindPFlag("build-jobs", cmd.Flags().Lookup("build-jobs"))
			cmdutils.ViperMustBindPFlag("dict", cmd.Flags().Lookup("dict"))
			cmdutils.ViperMustBindPFlag("engine-args", cmd.Flags().Lookup("engine-arg"))
			cmdutils.ViperMustBindPFlag("fuzz-test-args", cmd.Flags().Lookup("fuzz-test-arg"))
			cmdutils.ViperMustBindPFlag("seed-corpus-dirs", cmd.Flags().Lookup("seed-corpus"))
			cmdutils.ViperMustBindPFlag("timeout", cmd.Flags().Lookup("timeout"))
			cmdutils.ViperMustBindPFlag("project", cmd.Flags().Lookup("project"))
			cmdutils.ViperMustBindPFlag("server", cmd.Flags().Lookup("server"))

			// Fail early if the platform is not supported
			if runtime.GOOS != "linux" {
				system := strings.ToTitle(runtime.GOOS)
				if runtime.GOOS == "darwin" {
					system = "macOS"
				}
				err := errors.Errorf(`Starting a remote run is currently only supported on Linux. If you are
interested in using this feature on %s, please file an issue at
https://github.com/CodeIntelligenceTesting/cifuzz/issues`, system)
				log.Print(err.Error())
				return cmdutils.WrapSilentError(err)
			}

			projectDir, err := config.ParseProjectConfig(opts)
			if err != nil {
				log.Errorf(err, "Failed to parse cifuzz.yaml: %v", err.Error())
				return cmdutils.WrapSilentError(err)
			}
			opts.ProjectDir = projectDir
			opts.FuzzTests = args

			if opts.ProjectName != "" && !strings.HasPrefix(opts.ProjectName, "projects/") {
				opts.ProjectName = "projects/" + opts.ProjectName
			}

			return opts.Validate()
		},
		RunE: func(c *cobra.Command, args []string) error {
			opts.Stdout = c.OutOrStdout()
			opts.Stderr = c.OutOrStderr()
			cmd := runRemoteCmd{opts: opts}
			return cmd.run()
		},
	}

	cmdutils.AddBundleFlags(cmd)
	cmd.Flags().StringVarP(&opts.OutputPath, "output", "o", "", "Output path of the artifact (.tar.gz)")
	cmd.Flags().StringVar(&opts.Branch, "branch", "", "Branch name to use in the artifacts config. By default, the currently checked out git branch is used.")
	cmd.Flags().StringVar(&opts.Commit, "commit", "", "Commit to use in the artifacts config. By default, the head of the currently checked out git branch is used.")

	// TODO: Make the project name more accessible in the web app (currently
	//       it's only shown in the URL)
	cmd.Flags().StringP("project", "p", "", `The name of the CI Fuzz project you want to start a fuzzing run for,
e.g. "my-project-c170bc17".`)
	cmd.Flags().String("server", "https://app.code-intelligence.com", "Address of the fuzzing server")

	return cmd
}

func (c *runRemoteCmd) run() error {
	var err error

	// Obtain the API access token
	token := os.Getenv("CIFUZZ_API_TOKEN")
	if token == "" {
		token = access_tokens.Get(c.opts.Server)
	}

	if token == "" {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			b, err := io.ReadAll(os.Stdin)
			if err != nil {
				return errors.WithStack(err)
			}
			token = string(b)
		} else {
			fmt.Printf(`Enter an API access token and press Enter. You can generate a token for
your account at %s/dashboard/settings/account.`+"\n", c.opts.Server)
			reader := bufio.NewReader(os.Stdin)
			token, err = reader.ReadString('\n')
			if err != nil {
				return errors.WithStack(err)
			}
			token = strings.TrimSpace(token)
		}

		// Try to authenticate with the access token
		_, err = c.listProjects(token)
		if err != nil {
			return err
		}

		// Store the access token in the config file
		err = access_tokens.Set(c.opts.Server, token)
		if err != nil {
			return err
		}
	}

	if c.opts.ProjectName == "" {
		c.opts.ProjectName, err = c.selectProject(token)
		if err != nil {
			return err
		}
	}

	b := bundler.NewBundler(&c.opts.Opts)
	err = b.Bundle()
	if err != nil {
		return err
	}

	artifact, err := c.uploadArtifacts(b.Opts.OutputPath, token)
	if err != nil {
		return err
	}

	return c.startRemoteFuzzingRun(artifact, token)
}

func (c *runRemoteCmd) selectProject(token string) (string, error) {
	// Get the list of projects from the server
	projects, err := c.listProjects(token)
	if err != nil {
		return "", err
	}

	// Let the user select a project
	var displayNames []string
	var names []string
	for _, p := range projects {
		if p.OwnerOrganizationName != FeaturedProjectsOrganization {
			displayNames = append(displayNames, p.DisplayName)
			names = append(names, p.Name)
		}
	}
	maxLen := stringutil.MaxLen(displayNames)
	items := map[string]string{}
	for i := range displayNames {
		key := fmt.Sprintf("%-*s [%s]", maxLen, displayNames[i], strings.TrimPrefix(names[i], "projects/"))
		items[key] = names[i]
	}

	projectName, err := dialog.Select("Select the project you want to start a fuzzing run for", items)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return projectName, nil
}

func (c *runRemoteCmd) uploadArtifacts(path string, token string) (*artifact, error) {
	signalHandlerCtx, cancelSignalHandler := context.WithCancel(context.Background())
	routines, routinesCtx := errgroup.WithContext(signalHandlerCtx)

	// Cancel the routines context when receiving a termination signal
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	routines.Go(func() error {
		select {
		case <-routinesCtx.Done():
			return nil
		case s := <-sigs:
			log.Warnf("Received %s", s.String())
			return cmdutils.NewSignalError(s.(syscall.Signal))
		}
	})

	// Use a pipe to avoid reading the artifacts into memory at once
	r, w := io.Pipe()
	m := multipart.NewWriter(w)

	// Write the artifacts to the pipe
	routines.Go(func() error {
		defer w.Close()
		defer m.Close()

		part, err := m.CreateFormFile("fuzzing-artifacts", path)
		if err != nil {
			return errors.WithStack(err)
		}

		fileInfo, err := os.Stat(path)
		if err != nil {
			return errors.WithStack(err)
		}

		f, err := os.Open(path)
		if err != nil {
			return errors.WithStack(err)
		}
		defer f.Close()

		fmt.Println("Uploading...")
		progressR := progress.NewReader(f, fileInfo.Size(), "Upload complete")
		_, err = io.Copy(part, progressR)
		return errors.WithStack(err)
	})

	// Send a POST request with what we read from the pipe. The request
	// gets cancelled with the routines context is cancelled, which
	// happens if an error occurs in the io.Copy above or the user if
	// cancels the operation.
	var resp *http.Response
	routines.Go(func() error {
		defer r.Close()
		defer cancelSignalHandler()
		url := fmt.Sprintf("%s/v2/%s/artifacts/import", c.opts.Server, c.opts.ProjectName)
		req, err := http.NewRequestWithContext(routinesCtx, "POST", url, r)
		if err != nil {
			return errors.WithStack(err)
		}
		req.Header.Set("Content-Type", m.FormDataContentType())
		req.Header.Add("Authorization", "Bearer "+token)

		client := &http.Client{}
		resp, err = client.Do(req)
		return errors.WithStack(err)
	})

	err := routines.Wait()
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if resp.StatusCode != 200 {
		err := errors.Errorf("Uploading artifacts failed with %v", resp.Status)
		log.Error(err)
		return nil, cmdutils.WrapSilentError(err)
	}

	artifact := &artifact{}
	err = json.Unmarshal(body, artifact)
	if err != nil {
		err = errors.WithStack(err)
		log.Errorf(err, "Failed to parse response from upload artifacts API call: %s", err.Error())
		return nil, cmdutils.WrapSilentError(err)
	}

	return artifact, nil
}

func (c *runRemoteCmd) startRemoteFuzzingRun(artifact *artifact, token string) error {
	resp, err := c.sendRequest("POST", fmt.Sprintf("v1/%s:run", artifact.ResourceName), token)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		err := errors.Errorf("Starting remote fuzzing run failed with %v", resp.Status)
		log.Error(err)
		return cmdutils.WrapSilentError(err)
	}

	// Get the campaign run name from the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.WithStack(err)
	}
	var objmap map[string]json.RawMessage
	err = json.Unmarshal(body, &objmap)
	if err != nil {
		return errors.WithStack(err)
	}
	campaignRunNameJSON, ok := objmap["name"]
	if !ok {
		err := errors.Errorf("Server response doesn't include run name: %v", stringutil.PrettyString(objmap))
		log.Error(err)
		return cmdutils.WrapSilentError(err)
	}
	var campaignRunName string
	err = json.Unmarshal(campaignRunNameJSON, &campaignRunName)
	if err != nil {
		return errors.WithStack(err)
	}

	// TODO: Would be nice to be able to link to a page which immediately
	//       shows details about the run, but currently details are only
	//       shown on the "<fuzz target>/edit" page, which lists all runs
	//       of the fuzz target.
	log.Successf("Successfully started fuzzing run. Visit %s/dashboard/%s/overview to view the fuzzing run.",
		c.opts.Server, campaignRunName)

	return nil
}

func (c *runRemoteCmd) sendRequest(method, endpoint, token string) (*http.Response, error) {
	url := fmt.Sprintf("%s/%s", c.opts.Server, endpoint)
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	req.Header.Add("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return resp, nil
}

type project struct {
	Name                  string `json:"name"`
	DisplayName           string `json:"display_name"`
	OwnerOrganizationName string `json:"owner_organization_name"`
}

func (c *runRemoteCmd) listProjects(token string) ([]*project, error) {
	resp, err := c.sendRequest("GET", "v1/projects", token)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if resp.StatusCode != 200 {
		err := errors.Errorf("Listing projects failed with %v", resp.Status)
		log.Error(err)
		return nil, cmdutils.WrapSilentError(err)
	}

	var objmap map[string]json.RawMessage
	err = json.Unmarshal(body, &objmap)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var projects []*project
	err = json.Unmarshal(objmap["projects"], &projects)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return projects, nil
}
