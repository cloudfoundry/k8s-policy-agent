package cilium_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCilium(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cilium Translator Suite")
}
