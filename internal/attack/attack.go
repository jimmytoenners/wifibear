package attack

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/wifibear/wifibear/internal/config"
	"github.com/wifibear/wifibear/internal/result"
	"github.com/wifibear/wifibear/internal/tools"
	"github.com/wifibear/wifibear/pkg/wifi"
)

// Attack is the interface all attack types implement.
type Attack interface {
	Name() string
	Run(ctx context.Context, target *wifi.Target, iface string) (*result.CrackResult, error)
	CanAttack(target *wifi.Target) bool
	Priority() int
}

// StatusUpdate represents a real-time status message from an attack.
type StatusUpdate struct {
	Attack   string
	Message  string
	Progress float64 // 0.0 - 1.0
	Done     bool
	Success  bool
}

// Orchestrator sequences attacks against targets.
type Orchestrator struct {
	cfg      *config.Config
	attacks  []Attack
	statusCh chan StatusUpdate
	deps     *tools.DependencyChecker
	verbose  int
}

func NewOrchestrator(cfg *config.Config, statusCh chan StatusUpdate) *Orchestrator {
	deps := tools.NewDependencyChecker()

	o := &Orchestrator{
		cfg:      cfg,
		statusCh: statusCh,
		deps:     deps,
		verbose:  cfg.Output.Verbose,
	}

	o.buildAttackChain()
	return o
}

func (o *Orchestrator) buildAttackChain() {
	o.attacks = []Attack{
		NewDeauthAttack(o.cfg),
		NewPMKIDAttack(o.cfg),
		NewWPAAttack(o.cfg),
	}
}

// AttackTarget runs the attack chain against a single target.
func (o *Orchestrator) AttackTarget(ctx context.Context, target *wifi.Target, iface string) (*result.CrackResult, error) {
	if o.verbose > 0 {
		log.Printf("Starting attack chain for %s [%s] (%s)", target.ESSID, target.BSSID, target.Encryption)
	}

	attacks := o.selectAttacks(target)
	if len(attacks) == 0 {
		return nil, fmt.Errorf("no applicable attacks for %s (%s)", target.ESSID, target.Encryption)
	}

	for _, atk := range attacks {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if !atk.CanAttack(target) {
			continue
		}

		o.sendStatus(StatusUpdate{
			Attack:  atk.Name(),
			Message: "Starting...",
		})

		if o.verbose > 0 {
			log.Printf("Trying %s on %s", atk.Name(), target.ESSID)
		}

		res, err := atk.Run(ctx, target, iface)
		if err != nil {
			o.sendStatus(StatusUpdate{
				Attack:  atk.Name(),
				Message: fmt.Sprintf("Failed: %v", err),
				Done:    true,
			})
			if o.verbose > 0 {
				log.Printf("%s failed on %s: %v", atk.Name(), target.ESSID, err)
			}
			continue
		}

		if res != nil && res.Key != "" {
			o.sendStatus(StatusUpdate{
				Attack:  atk.Name(),
				Message: "Key found!",
				Done:    true,
				Success: true,
			})
			return res, nil
		}
	}

	return nil, fmt.Errorf("all attacks exhausted for %s", target.ESSID)
}

// AttackAll runs the attack chain against multiple targets.
func (o *Orchestrator) AttackAll(ctx context.Context, targets []*wifi.Target, iface string) []*result.CrackResult {
	var results []*result.CrackResult

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		res, err := o.AttackTarget(ctx, target, iface)
		if err != nil {
			continue
		}
		if res != nil {
			results = append(results, res)
		}
	}

	return results
}

func (o *Orchestrator) selectAttacks(target *wifi.Target) []Attack {
	var selected []Attack

	for _, atk := range o.attacks {
		if atk.CanAttack(target) {
			selected = append(selected, atk)
		}
	}

	return selected
}

func (o *Orchestrator) sendStatus(s StatusUpdate) {
	if o.statusCh == nil {
		return
	}
	select {
	case o.statusCh <- s:
	default:
	}
}

// AttackChainForTarget returns the ordered attack names for a target.
func (o *Orchestrator) AttackChainForTarget(target *wifi.Target) []string {
	var names []string
	for _, atk := range o.attacks {
		if atk.CanAttack(target) {
			names = append(names, atk.Name())
		}
	}
	return names
}

// EstimateDuration gives a rough time estimate for attacking a target.
func (o *Orchestrator) EstimateDuration(target *wifi.Target) time.Duration {
	var total time.Duration
	switch target.Encryption {
	case wifi.EncWPA2, wifi.EncWPA:
		total = o.cfg.Attack.PMKID.Timeout + o.cfg.Attack.WPA.HandshakeTimeout
	case wifi.EncWEP:
		total = o.cfg.Attack.WEP.Timeout
	}
	return total
}
