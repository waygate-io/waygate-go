package waygate

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"time"
)

type Words struct {
	Adjectives []string `json:"adjectives"`
	Colors     []string `json:"colors"`
	Animals    []string `json:"animals"`
}

type NameGenerator struct {
	words *Words
}

func NewNameGenerator() (generator *NameGenerator, err error) {

	rand.Seed(time.Now().UnixNano())

	bytes, err := fs.ReadFile("names/names.json")
	if err != nil {
		return
	}

	var words Words

	err = json.Unmarshal(bytes, &words)
	if err != nil {
		return
	}

	generator = &NameGenerator{
		words: &words,
	}

	return
}

func (g *NameGenerator) GenerateName() string {
	adjectiveIdx := rand.Intn(len(g.words.Adjectives))
	colorIdx := rand.Intn(len(g.words.Colors))
	animalIdx := rand.Intn(len(g.words.Animals))

	adjective := g.words.Adjectives[adjectiveIdx]
	color := g.words.Colors[colorIdx]
	animal := g.words.Animals[animalIdx]

	return fmt.Sprintf("%s-%s-%s", adjective, color, animal)
}
