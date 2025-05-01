package test

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/aquasecurity/defsec/pkg/rules"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/stretchr/testify/assert"
)

func Test_Failure(t *testing.T) {
	out, err, exit := runWithArgs("./testdata/fail", "--debug")
	assert.Equal(t, 1, exit)
	if t.Failed() {
		fmt.Println("StdErr:")
		fmt.Println(err)
		fmt.Println("StdOut:")
		fmt.Println(out)
	}
}

func Test_Pass(t *testing.T) {
	out, err, exit := runWithArgs("./testdata/pass")
	assert.NotEmpty(t, out)
	assert.Empty(t, err)
	assert.Equal(t, 0, exit)
}

func Test_GroupedResults(t *testing.T) {
	out, _, exit := runWithArgs("./testdata/group")
	assert.Contains(t, out, "Individual Causes")
	assert.Equal(t, 1, exit)
}

func Test_BadHCL(t *testing.T) {
	_, err, exit := runWithArgs("./testdata/badhcl")
	assert.Contains(t, err, "main.tf:1,29-30")
	assert.Equal(t, 1, exit)
}

func Test_ColouredOutputByDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("colours are not supported on windows")
	}
	out, _, exit := runWithArgs("./testdata/pass")
	assert.Contains(t, out, "\x1b[")
	assert.Equal(t, 0, exit)
}

func Test_LovelyOutputByDefault(t *testing.T) {
	out, _, exit := runWithArgs("./testdata/fail")
	assert.NotEmpty(t, parseLovely(t, out))
	assert.Equal(t, 1, exit)
}

func Test_ModuleDownloads(t *testing.T) {
	out, err, exit := runWithArgs("./testdata/external-module")
	assert.Empty(t, err)
	results := parseLovely(t, out)
	assert.NotEmpty(t, results)
	assert.Equal(t, 1, exit)
}

func Test_Ignores(t *testing.T) {
	out, err, exit := runWithArgs("./testdata/ignored")
	assert.Empty(t, err)
	results := parseLovely(t, out)
	assert.Empty(t, results)
	assert.Equal(t, 0, exit)
}

func Test_RootDirsOnly(t *testing.T) {
	out, err, exit := runWithArgs("./testdata/nested")
	assert.Empty(t, err)
	results := parseLovely(t, out)
	assert.Empty(t, results)
	assert.Equal(t, 0, exit)
}

func Test_PanicsAreRecovered(t *testing.T) {
	rules.Register(scan.Rule{}, func(s *state.State) (results scan.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if bucket.Name.EqualTo("panic") {
				panic("oh no")
			}
		}
		return results
	})
	_, err, exit := runWithArgs("./testdata/panic")
	assert.Contains(t, err, "job failed: oh no")
	assert.Equal(t, 1, exit)
}

func Test_WorkspaceDefault(t *testing.T) {
	out, err, exit := runWithArgs("./testdata/workspace")
	assert.Empty(t, err)
	results := parseLovely(t, out)
	assert.NotEmpty(t, results)
	assert.Equal(t, 1, exit)
}
