package main

import (
	"bytes"
	"fmt"
	"github.com/jessevdk/go-flags"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/xanzy/go-gitlab"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/config"
	"gopkg.in/src-d/go-git.v4/plumbing"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"gopkg.in/src-d/go-git.v4/plumbing/transport"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

var opts struct {
	GitlabAPI   string `long:"gitlab-api" required:"true" description:"Gitlab API endpoint"`
	GitlabToken string `long:"gitlab-token" required:"true" description:"Gitlab API access token"`
	SDKGroup    string `long:"sdk-group" required:"true" description:"Gitlab group for generated SDK"`
	PGBin       string `long:"protoc-bin" default:"protoc"`
	PGPlugin    string `long:"protoc-plugin" default:"/usr/local/bin/protoc-gen"`
}

var gapi *gitlab.Client
var sdkg *gitlab.Group

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})

	args, err := flags.Parse(&opts)
	if err != nil {
		panic(err)
	}

	gapi = gitlab.NewClient(nil, opts.GitlabToken)
	if err := gapi.SetBaseURL(opts.GitlabAPI); err != nil {
		panic(err)
	}

	if sdks, _, err := gapi.Groups.GetGroup(opts.SDKGroup); err != nil {
		panic(err)
	} else {
		sdkg = sdks
	}

	if len(args) < 2 {
		log.Fatal().Msg("usage syntax: protoc-sdk [options] project-id commit-sha [compare-sha]")
		os.Exit(1)
	}

	pid := args[0]
	sha := args[1]

	var prv string
	if len(args) > 2 {
		prv = args[2]
	}

	origin, _, err := gapi.Projects.GetProject(pid)
	if err != nil {
		panic(err)
	}

	log.Printf("Origin from %s", origin.WebURL)

	commit, _, err := gapi.Commits.GetCommit(origin.ID, sha)
	if err != nil {
		panic(err)
	}

	log.Printf("Commit [%s] by %s<%s> -> %s", commit.ShortID, commit.AuthorName, commit.AuthorEmail, commit.Title)

	pbs := pbsClone(origin)

	var wg sync.WaitGroup

	for _, pkg := range pbsPkgs(pbsDiff(origin.ID, sha, prv)) {
		wg.Add(1)
		go func(pkg string) {
			defer wg.Done()
			sdk := sdkClone(pkg)
			sdkClear(sdk)
			sdkGenerate(pkg, pbs, sdk)
			genComposer(pkg, sdk)
			sdkPush(sdk, commit)
			clsDir(sdk)
		}(pkg)
	}

	wg.Wait()

	clsDir(pbs)
}

func clsDir(dir string) {
	if err := os.RemoveAll(dir); err != nil {
		log.Warn().Err(err)
	}
}

func pbsDiff(pid interface{}, current, previous string) []*gitlab.Diff {
	if previous == "" {
		diff, _, err := gapi.Commits.GetCommitDiff(pid, current, &gitlab.GetCommitDiffOptions{PerPage: 9999})
		if err != nil {
			panic(err)
		}
		return diff
	}

	compared, _, err := gapi.Repositories.Compare(pid, &gitlab.CompareOptions{From: &previous, To: &current})
	if err != nil {
		panic(err)
	}

	return compared.Diffs
}

func pbsPkgs(diffs []*gitlab.Diff) []string {
	pkgs := make([]string, 0)
	exists := make(map[string]int)

	for _, stat := range diffs {
		spts := strings.Split(stat.NewPath, "/")
		if len(spts) < 2 {
			continue
		}
		dir := spts[0]
		file := spts[len(spts)-1]
		if !strings.HasSuffix(file, ".proto") {
			continue
		}
		if _, ok := exists[dir]; !ok {
			exists[dir] = 1
			pkgs = append(pkgs, dir)
		}
	}

	return pkgs
}

func sdkClone(pkg string) string {
	p, r, e := gapi.Projects.GetProject(fmt.Sprintf("%s/%s", opts.SDKGroup, pkg))
	if e != nil {
		if r.StatusCode == 404 {
			create := &gitlab.CreateProjectOptions{
				Name:        &pkg,
				Path:        &pkg,
				NamespaceID: &sdkg.ID,
				Visibility:  gitlab.Visibility(gitlab.PublicVisibility),
			}
			if cp, _, e := gapi.Projects.CreateProject(create); e != nil {
				panic(e)
			} else {
				p = cp
				log.Info().Msgf("Automatic created sdk project -> %s", cp.PathWithNamespace)
			}
		} else {
			panic(e)
		}
	}

	return gitClone(p.HTTPURLToRepo, pkg)
}

func sdkPush(sdk string, commit *gitlab.Commit) {
	repo, err := git.PlainOpen(sdk)
	if err != nil {
		panic(err)
	}

	wt, _ := repo.Worktree()
	wts, _ := wt.Status()

	if wts.IsClean() {
		log.Info().Msg("Working tree clean, skipped")
		return
	} else {
		log.Printf("Work tree status in %s\n%s", sdk, wts.String())
	}

	for path, fs := range wts {
		if fs.Worktree == git.Untracked {
			if _, err := wt.Add(path); err != nil {
				panic(err)
			}
		}
	}

	if sha, err := wt.Commit(fmt.Sprintf("Ref %s by <%s> : %s", commit.ShortID, commit.AuthorName, commit.Title), &git.CommitOptions{
		All: true,
		Author: &object.Signature{
			Name:  commit.CommitterEmail,
			Email: commit.CommitterEmail,
			When:  *commit.CommittedDate,
		},
	}); err != nil {
		panic(err)
	} else {
		commit, _ := repo.CommitObject(sha)
		log.Printf("New commit > %s :: %s", commit.ID(), commit.Message)
	}

	log.Info().Msgf("Git pushing to remote of %s", sdk)

	if err := repo.Push(&git.PushOptions{}); err != nil {
		panic(err)
	}

	log.Printf("Git push DONE of %s", sdk)
}

func pbsClone(from *gitlab.Project) string {
	return gitClone(from.HTTPURLToRepo, fmt.Sprintf("%s-%d", from.Name, from.ID))
}

func sdkGenerate(pkg, pbs, sdk string) {
	log.Info().Msgf("Start to generate sdk of [%s]", pkg)

	if err := filepath.Walk(fmt.Sprintf("%s/%s", pbs, pkg), func(path string, file os.FileInfo, err error) error {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".proto") {
			return nil
		}

		cmdRun(
			fmt.Sprintf("[PB] processing %s/%s", pkg, file.Name()),
			opts.PGBin,
			"-I",
			pbs,
			fmt.Sprintf("--plugin=protoc-gen-custom=%s", opts.PGPlugin),
			fmt.Sprintf("--custom_out=%s", sdk),
			path,
		)

		return nil
	}); err != nil {
		panic(err)
	}
}

func sdkClear(dir string) {
	fd, err := os.Open(dir)
	if err != nil {
		panic(err)
	}

	defer fd.Close()

	if names, err := fd.Readdirnames(-1); err != nil {
		panic(err)
	} else {
		for _, name := range names {
			if string(name[0]) == "." {
				continue
			} else {
				if err := os.RemoveAll(dir + "/" + name); err != nil {
					panic(err)
				}
			}
		}
	}
}

func gitClone(http string, dir string) string {
	u, _ := url.Parse(http)
	u.User = url.UserPassword("token", opts.GitlabToken)

	tmp := tmpDir(dir)

	log.Printf("Start to clone %s -> %s", http, dir)

	if _, err := git.PlainClone(tmp, false, &git.CloneOptions{
		URL:           u.String(),
		ReferenceName: plumbing.Master,
		SingleBranch:  true,
	}); err != nil {
		if err == transport.ErrEmptyRemoteRepository {
			if repo, err := git.PlainInit(tmp, false); err != nil {
				panic(err)
			} else {
				if _, err := repo.CreateRemote(&config.RemoteConfig{
					Name: git.DefaultRemoteName,
					URLs: []string{u.String()},
				}); err != nil {
					panic(err)
				} else {
					log.Info().Msgf("Initialized empty git repo for %s", dir)
				}
			}
		} else {
			panic(err)
		}
	}

	return tmp
}

func cmdRun(tip, bin string, args ...string) []byte {
	cmd := exec.Command(bin, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if tip != "" {
		log.Info().Msg(tip)
	}

	if err := cmd.Run(); err != nil {
		fmt.Print(stderr.String())
		panic(err)
	} else {
		log.Printf("--- %s DONE", strings.ToUpper(bin))
	}

	return stdout.Bytes()
}

func tmpDir(pkg string) string {
	if path, err := ioutil.TempDir("", pkg); err != nil {
		panic(err)
	} else {
		return path
	}
}
