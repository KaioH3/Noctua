package anomaly

import (
	"math"
	"math/rand"
)

type iTreeNode struct {
	Left      *iTreeNode
	Right     *iTreeNode
	SplitAttr int
	SplitVal  float64
	Size      int // number of samples at this node (for external nodes)
}

type IsolationTree struct {
	root     *iTreeNode
	maxDepth int
}

type IsolationForest struct {
	Trees      []*IsolationTree
	SampleSize int
	NumTrees   int
	rng        *rand.Rand
}

func NewIsolationForest(numTrees, sampleSize int) *IsolationForest {
	return &IsolationForest{
		NumTrees:   numTrees,
		SampleSize: sampleSize,
		rng:        rand.New(rand.NewSource(42)),
	}
}

func (f *IsolationForest) Fit(data [][]float64) {
	if len(data) == 0 {
		return
	}

	maxDepth := int(math.Ceil(math.Log2(float64(f.SampleSize))))
	f.Trees = make([]*IsolationTree, f.NumTrees)

	for i := 0; i < f.NumTrees; i++ {
		sample := f.subsample(data)
		tree := &IsolationTree{maxDepth: maxDepth}
		tree.root = f.buildTree(sample, 0, maxDepth)
		f.Trees[i] = tree
	}
}

func (f *IsolationForest) Score(point []float64) float64 {
	if len(f.Trees) == 0 {
		return 0
	}

	var totalPath float64
	for _, tree := range f.Trees {
		totalPath += float64(pathLength(point, tree.root, 0))
	}
	avgPath := totalPath / float64(len(f.Trees))

	n := float64(f.SampleSize)
	c := avgPathLength(n)
	if c == 0 {
		return 0
	}

	return math.Pow(2, -avgPath/c)
}

func (f *IsolationForest) subsample(data [][]float64) [][]float64 {
	n := len(data)
	size := f.SampleSize
	if size > n {
		size = n
	}

	indices := f.rng.Perm(n)[:size]
	sample := make([][]float64, size)
	for i, idx := range indices {
		sample[i] = data[idx]
	}
	return sample
}

func (f *IsolationForest) buildTree(data [][]float64, depth, maxDepth int) *iTreeNode {
	if len(data) <= 1 || depth >= maxDepth {
		return &iTreeNode{Size: len(data)}
	}

	nFeatures := len(data[0])
	attr := f.rng.Intn(nFeatures)

	minVal, maxVal := data[0][attr], data[0][attr]
	for _, row := range data[1:] {
		if row[attr] < minVal {
			minVal = row[attr]
		}
		if row[attr] > maxVal {
			maxVal = row[attr]
		}
	}

	if minVal == maxVal {
		return &iTreeNode{Size: len(data)}
	}

	splitVal := minVal + f.rng.Float64()*(maxVal-minVal)

	var left, right [][]float64
	for _, row := range data {
		if row[attr] < splitVal {
			left = append(left, row)
		} else {
			right = append(right, row)
		}
	}

	return &iTreeNode{
		SplitAttr: attr,
		SplitVal:  splitVal,
		Left:      f.buildTree(left, depth+1, maxDepth),
		Right:     f.buildTree(right, depth+1, maxDepth),
	}
}

func pathLength(point []float64, node *iTreeNode, depth int) float64 {
	if node == nil {
		return float64(depth)
	}
	if node.Left == nil && node.Right == nil {
		return float64(depth) + avgPathLength(float64(node.Size))
	}
	if node.SplitAttr >= len(point) {
		return float64(depth)
	}
	if point[node.SplitAttr] < node.SplitVal {
		return pathLength(point, node.Left, depth+1)
	}
	return pathLength(point, node.Right, depth+1)
}

func avgPathLength(n float64) float64 {
	if n <= 1 {
		return 0
	}
	if n == 2 {
		return 1
	}
	return 2*(math.Log(n-1)+0.5772156649) - 2*(n-1)/n
}
