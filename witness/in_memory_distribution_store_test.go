/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestInMemoryDistributionStore_RoundTrip(t *testing.T) {
	s := NewInMemoryDistributionStore()
	ctx := context.Background()

	got, err := s.LoadRound(ctx, "unknown")
	if err != nil {
		t.Fatalf("LoadRound unknown: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for unknown round, got %+v", got)
	}

	round := &DistributionRoundResult{
		RoundID:     "round-1",
		WindowStart: time.Unix(0, 0),
		WindowEnd:   time.Unix(3600, 0),
		StartedAt:   time.Unix(3600, 0),
	}
	if err := s.SaveRound(ctx, round); err != nil {
		t.Fatalf("SaveRound: %v", err)
	}

	got, err = s.LoadRound(ctx, "round-1")
	if err != nil {
		t.Fatalf("LoadRound saved: %v", err)
	}
	if got == nil || got.RoundID != "round-1" {
		t.Errorf("round not retrieved: %+v", got)
	}
}

func TestInMemoryDistributionStore_DuplicateRejected(t *testing.T) {
	s := NewInMemoryDistributionStore()
	ctx := context.Background()

	round := &DistributionRoundResult{RoundID: "dup"}
	if err := s.SaveRound(ctx, round); err != nil {
		t.Fatalf("first SaveRound: %v", err)
	}
	err := s.SaveRound(ctx, round)
	if err == nil {
		t.Fatal("want duplicate error, got nil")
	}
	if !errors.Is(err, ErrRoundAlreadyProcessed) {
		t.Errorf("want ErrRoundAlreadyProcessed, got %v", err)
	}
}

func TestInMemoryDistributionStore_NilRound(t *testing.T) {
	s := NewInMemoryDistributionStore()
	if err := s.SaveRound(context.Background(), nil); err == nil {
		t.Fatal("want nil-round error")
	}
}

func TestInMemoryDistributionStore_ConcurrentSaves(t *testing.T) {
	s := NewInMemoryDistributionStore()
	ctx := context.Background()

	var wg sync.WaitGroup
	const n = 32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = s.SaveRound(ctx, &DistributionRoundResult{
				RoundID: (func() string {
					// Avoid strconv import by formatting manually.
					b := []byte{'r', '-'}
					val := i
					if val == 0 {
						return string(append(b, '0'))
					}
					var digits []byte
					for val > 0 {
						digits = append([]byte{byte('0' + val%10)}, digits...)
						val /= 10
					}
					return string(append(b, digits...))
				})(),
			})
		}(i)
	}
	wg.Wait()

	// Verify every round we saved can be loaded.
	for i := 0; i < n; i++ {
		id := "r-0"
		if i > 0 {
			id = (func() string {
				b := []byte{'r', '-'}
				val := i
				var digits []byte
				for val > 0 {
					digits = append([]byte{byte('0' + val%10)}, digits...)
					val /= 10
				}
				return string(append(b, digits...))
			})()
		}
		got, err := s.LoadRound(ctx, id)
		if err != nil {
			t.Errorf("LoadRound(%s): %v", id, err)
		}
		if got == nil {
			t.Errorf("round %s missing after concurrent save", id)
		}
	}
}
