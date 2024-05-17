package multilineexperiment

type Trie struct {
	states    [][]int
	nextState int
	maxToken  int
	table     []int
	rowSize   int
}

func NewTrie() *Trie {
	return &Trie{
		states:    make([][]int, 0),
		nextState: 1,
	}
}

func (t *Trie) Add(input []Token) {
	currState := 0
	for _, value := range input {
		var row []int
		if currState >= len(t.states) {
			replace := make([][]int, currState+1)
			copy(replace, t.states)
			t.states = replace
		} else {
			row = t.states[currState]
		}
		t.states[currState], currState = t.transition(row, int(value))
	}
}

func (t *Trie) transition(row []int, value int) ([]int, int) {
	if value > t.maxToken {
		t.maxToken = value
	}
	if value >= len(row) {
		replace := make([]int, value+1)
		copy(replace, row)
		row = replace
	}
	if row[value] > 0 {
		return row, row[value]
	}
	row[value] = t.nextState
	t.nextState += 1
	return row, row[value]
}

func (t *Trie) Compile() {
	t.rowSize = nextLargestPowerOf2(t.maxToken + 1)
	t.table = make([]int, len(t.states)*t.rowSize)
	for i, row := range t.states {
		// copy the row
		for j, value := range row {
			t.table[i*t.rowSize+j] = value
		}
	}
}

func nextLargestPowerOf2(n int) int {
	answer := n
	for n > 0 {
		answer = n
		n = n & (n - 1)
	}
	return answer
}

func (t *Trie) MatchProbability(input []Token) float64 {
	currState := 0
	for _, value := range input {
		k := int(value) + t.rowSize*currState
		if k >= len(t.table) {
			return 0.0
		}
		currState = t.table[k]
		if currState == 0 {
			return 0.0
		}
	}
	return 1.0
}
