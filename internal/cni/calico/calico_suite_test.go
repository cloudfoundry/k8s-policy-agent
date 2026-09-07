package calico_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCalico(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Calico Translator Suite")
}
