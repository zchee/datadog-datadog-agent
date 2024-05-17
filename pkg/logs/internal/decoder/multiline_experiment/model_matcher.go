package multilineexperiment

type ModelMatcher interface {
	Add(input []Token)
	Compile()
	MatchProbability([]Token) float64
	Show()
}
