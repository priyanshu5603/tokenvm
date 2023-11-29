// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"github.com/ava-labs/avalanchego/utils/wrappers"
	"github.com/ava-labs/avalanchego/vms/platformvm/warp"
	"github.com/ava-labs/hypersdk/chain"
	"github.com/ava-labs/hypersdk/codec"

	"tokenvm/actions"
	"tokenvm/auth"
	"tokenvm/consts"
)

// Setup types
func init() {
	consts.ActionRegistry = codec.NewTypeParser[chain.Action, *warp.Message]()
	consts.AuthRegistry = codec.NewTypeParser[chain.Auth, *warp.Message]()

	errs := &wrappers.Errs{}
	errs.Add(
		// When registering new actions, ALWAYS make sure to append at the end.
		consts.ActionRegistry.Register(&actions.Transfer{}, actions.UnmarshalTransfer, false),

		// TODO: register action: actions.CreateAsset
		// TODO: register action: actions.MintAsset
		consts.ActionRegistry.Register(&actions.BurnAsset{}, actions.UnmarshalBurnAsset, false),
		consts.ActionRegistry.Register(&actions.ModifyAsset{}, actions.UnmarshalModifyAsset, false),

		consts.ActionRegistry.Register(&actions.CreateOrder{}, actions.UnmarshalCreateOrder, false),
		consts.ActionRegistry.Register(&actions.FillOrder{}, actions.UnmarshalFillOrder, false),
		consts.ActionRegistry.Register(&actions.CloseOrder{}, actions.UnmarshalCloseOrder, false),

		consts.ActionRegistry.Register(&actions.ImportAsset{}, actions.UnmarshalImportAsset, true),
		consts.ActionRegistry.Register(&actions.ExportAsset{}, actions.UnmarshalExportAsset, false),

		// When registering new auth, ALWAYS make sure to append at the end.
		consts.AuthRegistry.Register(&auth.ED25519{}, auth.UnmarshalED25519, false),
	)
	if errs.Errored() {
		panic(errs.Err)
	}
}



// actions/create_asset.go

package actions

import (
	"context"

	"tokenvm/auth"
	"tokenvm/storage"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/vms/platformvm/warp"
	"github.com/ava-labs/hypersdk/chain"
	"github.com/ava-labs/hypersdk/codec"
	"github.com/ava-labs/hypersdk/utils"
)

var _ chain.Action = (*CreateAsset)(nil)

type CreateAsset struct {
	// Metadata is creator-specified information about the asset. This can be
	// modified using the [ModifyAsset] action.
	Metadata []byte `json:"metadata"`
}

func (*CreateAsset) StateKeys(_ chain.Auth, txID ids.ID) [][]byte {
	return [][]byte{storage.PrefixAssetKey(txID)}
}

func (c *CreateAsset) Execute(
	ctx context.Context,
	r chain.Rules,
	db chain.Database,
	_ int64,
	rauth chain.Auth,
	txID ids.ID,
	_ bool,
) (*chain.Result, error) {
	actor := auth.GetActor(rauth)
	unitsUsed := c.MaxUnits(r) // max units == units
	if len(c.Metadata) > MaxMetadataSize {
		return &chain.Result{Success: false, Units: unitsUsed, Output: OutputMetadataTooLarge}, nil
	}
	// It should only be possible to overwrite an existing asset if there is
	// a hash collision.
	if err := storage.SetAsset(ctx, db, txID, c.Metadata, 0, actor, false); err != nil {
		return &chain.Result{Success: false, Units: unitsUsed, Output: utils.ErrBytes(err)}, nil
	}
	return &chain.Result{Success: true, Units: unitsUsed}, nil
}

func (c *CreateAsset) MaxUnits(chain.Rules) uint64 {
	// We use size as the price of this transaction but we could just as easily
	// use any other calculation.
	return uint64(len(c.Metadata))
}

func (c *CreateAsset) Marshal(p *codec.Packer) {
	p.PackBytes(c.Metadata)
}

func UnmarshalCreateAsset(p *codec.Packer, _ *warp.Message) (chain.Action, error) {
	var create CreateAsset
	p.UnpackBytes(MaxMetadataSize, false, &create.Metadata)
	return &create, p.Err()
}

func (*CreateAsset) ValidRange(chain.Rules) (int64, int64) {
	// Returning -1, -1 means that the action is always valid.
	return -1, -1
}


package actions

import (
	"context"

	"github.com/ava-labs/avalanchego/ids"
	smath "github.com/ava-labs/avalanchego/utils/math"
	"github.com/ava-labs/avalanchego/vms/platformvm/warp"

	"tokenvm/auth"
	"tokenvm/storage"

	"github.com/ava-labs/hypersdk/chain"
	"github.com/ava-labs/hypersdk/codec"
	"github.com/ava-labs/hypersdk/consts"
	"github.com/ava-labs/hypersdk/crypto"
	"github.com/ava-labs/hypersdk/utils"
)

var _ chain.Action = (*MintAsset)(nil)

type MintAsset struct {
	// To is the recipient of the [Value].
	To crypto.PublicKey `json:"to"`

	// Asset is the [TxID] that created the asset.
	Asset ids.ID `json:"asset"`

	// Number of assets to mint to [To].
	Value uint64 `json:"value"`
}

func (m *MintAsset) StateKeys(chain.Auth, ids.ID) [][]byte {
	return [][]byte{
		storage.PrefixAssetKey(m.Asset),
		storage.PrefixBalanceKey(m.To, m.Asset),
	}
}

func (m *MintAsset) Execute(
	ctx context.Context,
	r chain.Rules,
	db chain.Database,
	_ int64,
	rauth chain.Auth,
	_ ids.ID,
	_ bool,
) (*chain.Result, error) {
	actor := auth.GetActor(rauth)
	unitsUsed := m.MaxUnits(r) // max units == units
	if m.Asset == ids.Empty {
		return &chain.Result{Success: false, Units: unitsUsed, Output: OutputAssetIsNative}, nil
	}
	if m.Value == 0 {
		return &chain.Result{Success: false, Units: unitsUsed, Output: OutputValueZero}, nil
	}
	exists, metadata, supply, owner, isWarp, err := storage.GetAsset(ctx, db, m.Asset)
	if err != nil {
		return &chain.Result{Success: false, Units: unitsUsed, Output: utils.ErrBytes(err)}, nil
	}
	if !exists {
		return &chain.Result{Success: false, Units: unitsUsed, Output: OutputAssetMissing}, nil
	}
	if isWarp {
		return &chain.Result{Success: false, Units: unitsUsed, Output: OutputWarpAsset}, nil
	}
	if owner != actor {
		return &chain.Result{
			Success: false,
			Units:   unitsUsed,
			Output:  OutputWrongOwner,
		}, nil
	}
	newSupply, err := smath.Add64(supply, m.Value)
	if err != nil {
		return &chain.Result{Success: false, Units: unitsUsed, Output: utils.ErrBytes(err)}, nil
	}
	if err := storage.SetAsset(ctx, db, m.Asset, metadata, newSupply, actor, isWarp); err != nil {
		return &chain.Result{Success: false, Units: unitsUsed, Output: utils.ErrBytes(err)}, nil
	}
	if err := storage.AddBalance(ctx, db, m.To, m.Asset, m.Value); err != nil {
		return &chain.Result{Success: false, Units: unitsUsed, Output: utils.ErrBytes(err)}, nil
	}
	return &chain.Result{Success: true, Units: unitsUsed}, nil
}

func (*MintAsset) MaxUnits(chain.Rules) uint64 {
	// We use size as the price of this transaction but we could just as easily
	// use any other calculation.
	return crypto.PublicKeyLen + consts.IDLen + consts.Uint64Len
}

func (m *MintAsset) Marshal(p *codec.Packer) {
	p.PackPublicKey(m.To)
	p.PackID(m.Asset)
	p.PackUint64(m.Value)
}

func UnmarshalMintAsset(p *codec.Packer, _ *warp.Message) (chain.Action, error) {
	var mint MintAsset
	p.UnpackPublicKey(true, &mint.To) // cannot mint to blackhole
	p.UnpackID(true, &mint.Asset)     // empty ID is the native asset
	mint.Value = p.UnpackUint64(true)
	return &mint, p.Err()
}

func (*MintAsset) ValidRange(chain.Rules) (int64, int64) {
	// Returning -1, -1 means that the action is always valid.
	return -1, -1
}

