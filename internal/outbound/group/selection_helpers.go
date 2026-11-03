package group

import "time"

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func orderCurrent(order []int, cur int) []int {
	out := []int{cur}
	for _, i := range order {
		if i != cur {
			out = append(out, i)
		}
	}
	return out
}
