// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Code generated by tailscale/cmd/viewer; DO NOT EDIT.

package tailcfg

import (
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"go4.org/mem"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/opt"
	"tailscale.com/types/structs"
	"tailscale.com/types/tkatype"
	"tailscale.com/types/views"
)

//go:generate go run tailscale.com/cmd/cloner  -clonefunc=true -type=User,Node,Hostinfo,NetInfo,Login,DNSConfig,RegisterResponse,DERPRegion,DERPMap,DERPNode,SSHRule,SSHAction,SSHPrincipal,ControlDialPlan

// View returns a readonly view of User.
func (p *User) View() UserView {
	return UserView{ж: p}
}

// UserView provides a read-only view over User.
//
// Its methods should only be called if `Valid()` returns true.
type UserView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *User
}

// Valid reports whether underlying value is non-nil.
func (v UserView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v UserView) AsStruct() *User {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v UserView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *UserView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x User
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v UserView) ID() UserID                   { return v.ж.ID }
func (v UserView) LoginName() string            { return v.ж.LoginName }
func (v UserView) DisplayName() string          { return v.ж.DisplayName }
func (v UserView) ProfilePicURL() string        { return v.ж.ProfilePicURL }
func (v UserView) Domain() string               { return v.ж.Domain }
func (v UserView) Logins() views.Slice[LoginID] { return views.SliceOf(v.ж.Logins) }
func (v UserView) Created() time.Time           { return v.ж.Created }

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _UserViewNeedsRegeneration = User(struct {
	ID            UserID
	LoginName     string
	DisplayName   string
	ProfilePicURL string
	Domain        string
	Logins        []LoginID
	Created       time.Time
}{})

// View returns a readonly view of Node.
func (p *Node) View() NodeView {
	return NodeView{ж: p}
}

// NodeView provides a read-only view over Node.
//
// Its methods should only be called if `Valid()` returns true.
type NodeView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *Node
}

// Valid reports whether underlying value is non-nil.
func (v NodeView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v NodeView) AsStruct() *Node {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v NodeView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *NodeView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x Node
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v NodeView) ID() NodeID                      { return v.ж.ID }
func (v NodeView) StableID() StableNodeID          { return v.ж.StableID }
func (v NodeView) Name() string                    { return v.ж.Name }
func (v NodeView) User() UserID                    { return v.ж.User }
func (v NodeView) Sharer() UserID                  { return v.ж.Sharer }
func (v NodeView) Key() key.NodePublic             { return v.ж.Key }
func (v NodeView) KeyExpiry() time.Time            { return v.ж.KeyExpiry }
func (v NodeView) KeySignature() mem.RO            { return mem.B(v.ж.KeySignature) }
func (v NodeView) Machine() key.MachinePublic      { return v.ж.Machine }
func (v NodeView) DiscoKey() key.DiscoPublic       { return v.ж.DiscoKey }
func (v NodeView) Addresses() views.IPPrefixSlice  { return views.IPPrefixSliceOf(v.ж.Addresses) }
func (v NodeView) AllowedIPs() views.IPPrefixSlice { return views.IPPrefixSliceOf(v.ж.AllowedIPs) }
func (v NodeView) Endpoints() views.Slice[string]  { return views.SliceOf(v.ж.Endpoints) }
func (v NodeView) DERP() string                    { return v.ж.DERP }
func (v NodeView) Hostinfo() HostinfoView          { return v.ж.Hostinfo }
func (v NodeView) Created() time.Time              { return v.ж.Created }
func (v NodeView) Cap() CapabilityVersion          { return v.ж.Cap }
func (v NodeView) Tags() views.Slice[string]       { return views.SliceOf(v.ж.Tags) }
func (v NodeView) PrimaryRoutes() views.IPPrefixSlice {
	return views.IPPrefixSliceOf(v.ж.PrimaryRoutes)
}
func (v NodeView) LastSeen() *time.Time {
	if v.ж.LastSeen == nil {
		return nil
	}
	x := *v.ж.LastSeen
	return &x
}

func (v NodeView) Online() *bool {
	if v.ж.Online == nil {
		return nil
	}
	x := *v.ж.Online
	return &x
}

func (v NodeView) KeepAlive() bool                   { return v.ж.KeepAlive }
func (v NodeView) MachineAuthorized() bool           { return v.ж.MachineAuthorized }
func (v NodeView) Capabilities() views.Slice[string] { return views.SliceOf(v.ж.Capabilities) }
func (v NodeView) UnsignedPeerAPIOnly() bool         { return v.ж.UnsignedPeerAPIOnly }
func (v NodeView) ComputedName() string              { return v.ж.ComputedName }
func (v NodeView) ComputedNameWithHost() string      { return v.ж.ComputedNameWithHost }
func (v NodeView) DataPlaneAuditLogID() string       { return v.ж.DataPlaneAuditLogID }
func (v NodeView) Expired() bool                     { return v.ж.Expired }
func (v NodeView) SelfNodeV4MasqAddrForThisPeer() *netip.Addr {
	if v.ж.SelfNodeV4MasqAddrForThisPeer == nil {
		return nil
	}
	x := *v.ж.SelfNodeV4MasqAddrForThisPeer
	return &x
}

func (v NodeView) SelfNodeV6MasqAddrForThisPeer() *netip.Addr {
	if v.ж.SelfNodeV6MasqAddrForThisPeer == nil {
		return nil
	}
	x := *v.ж.SelfNodeV6MasqAddrForThisPeer
	return &x
}

func (v NodeView) IsWireGuardOnly() bool  { return v.ж.IsWireGuardOnly }
func (v NodeView) Equal(v2 NodeView) bool { return v.ж.Equal(v2.ж) }

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _NodeViewNeedsRegeneration = Node(struct {
	ID                            NodeID
	StableID                      StableNodeID
	Name                          string
	User                          UserID
	Sharer                        UserID
	Key                           key.NodePublic
	KeyExpiry                     time.Time
	KeySignature                  tkatype.MarshaledSignature
	Machine                       key.MachinePublic
	DiscoKey                      key.DiscoPublic
	Addresses                     []netip.Prefix
	AllowedIPs                    []netip.Prefix
	Endpoints                     []string
	DERP                          string
	Hostinfo                      HostinfoView
	Created                       time.Time
	Cap                           CapabilityVersion
	Tags                          []string
	PrimaryRoutes                 []netip.Prefix
	LastSeen                      *time.Time
	Online                        *bool
	KeepAlive                     bool
	MachineAuthorized             bool
	Capabilities                  []string
	UnsignedPeerAPIOnly           bool
	ComputedName                  string
	computedHostIfDifferent       string
	ComputedNameWithHost          string
	DataPlaneAuditLogID           string
	Expired                       bool
	SelfNodeV4MasqAddrForThisPeer *netip.Addr
	SelfNodeV6MasqAddrForThisPeer *netip.Addr
	IsWireGuardOnly               bool
}{})

// View returns a readonly view of Hostinfo.
func (p *Hostinfo) View() HostinfoView {
	return HostinfoView{ж: p}
}

// HostinfoView provides a read-only view over Hostinfo.
//
// Its methods should only be called if `Valid()` returns true.
type HostinfoView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *Hostinfo
}

// Valid reports whether underlying value is non-nil.
func (v HostinfoView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v HostinfoView) AsStruct() *Hostinfo {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v HostinfoView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *HostinfoView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x Hostinfo
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v HostinfoView) IPNVersion() string      { return v.ж.IPNVersion }
func (v HostinfoView) FrontendLogID() string   { return v.ж.FrontendLogID }
func (v HostinfoView) BackendLogID() string    { return v.ж.BackendLogID }
func (v HostinfoView) OS() string              { return v.ж.OS }
func (v HostinfoView) OSVersion() string       { return v.ж.OSVersion }
func (v HostinfoView) Container() opt.Bool     { return v.ж.Container }
func (v HostinfoView) Env() string             { return v.ж.Env }
func (v HostinfoView) Distro() string          { return v.ж.Distro }
func (v HostinfoView) DistroVersion() string   { return v.ж.DistroVersion }
func (v HostinfoView) DistroCodeName() string  { return v.ж.DistroCodeName }
func (v HostinfoView) App() string             { return v.ж.App }
func (v HostinfoView) Desktop() opt.Bool       { return v.ж.Desktop }
func (v HostinfoView) Package() string         { return v.ж.Package }
func (v HostinfoView) DeviceModel() string     { return v.ж.DeviceModel }
func (v HostinfoView) PushDeviceToken() string { return v.ж.PushDeviceToken }
func (v HostinfoView) Hostname() string        { return v.ж.Hostname }
func (v HostinfoView) ShieldsUp() bool         { return v.ж.ShieldsUp }
func (v HostinfoView) ShareeNode() bool        { return v.ж.ShareeNode }
func (v HostinfoView) NoLogsNoSupport() bool   { return v.ж.NoLogsNoSupport }
func (v HostinfoView) WireIngress() bool       { return v.ж.WireIngress }
func (v HostinfoView) AllowsUpdate() bool      { return v.ж.AllowsUpdate }
func (v HostinfoView) Machine() string         { return v.ж.Machine }
func (v HostinfoView) GoArch() string          { return v.ж.GoArch }
func (v HostinfoView) GoArchVar() string       { return v.ж.GoArchVar }
func (v HostinfoView) GoVersion() string       { return v.ж.GoVersion }
func (v HostinfoView) RoutableIPs() views.IPPrefixSlice {
	return views.IPPrefixSliceOf(v.ж.RoutableIPs)
}
func (v HostinfoView) RequestTags() views.Slice[string]  { return views.SliceOf(v.ж.RequestTags) }
func (v HostinfoView) Services() views.Slice[Service]    { return views.SliceOf(v.ж.Services) }
func (v HostinfoView) NetInfo() NetInfoView              { return v.ж.NetInfo.View() }
func (v HostinfoView) SSH_HostKeys() views.Slice[string] { return views.SliceOf(v.ж.SSH_HostKeys) }
func (v HostinfoView) Cloud() string                     { return v.ж.Cloud }
func (v HostinfoView) Userspace() opt.Bool               { return v.ж.Userspace }
func (v HostinfoView) UserspaceRouter() opt.Bool         { return v.ж.UserspaceRouter }
func (v HostinfoView) Equal(v2 HostinfoView) bool        { return v.ж.Equal(v2.ж) }

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _HostinfoViewNeedsRegeneration = Hostinfo(struct {
	IPNVersion      string
	FrontendLogID   string
	BackendLogID    string
	OS              string
	OSVersion       string
	Container       opt.Bool
	Env             string
	Distro          string
	DistroVersion   string
	DistroCodeName  string
	App             string
	Desktop         opt.Bool
	Package         string
	DeviceModel     string
	PushDeviceToken string
	Hostname        string
	ShieldsUp       bool
	ShareeNode      bool
	NoLogsNoSupport bool
	WireIngress     bool
	AllowsUpdate    bool
	Machine         string
	GoArch          string
	GoArchVar       string
	GoVersion       string
	RoutableIPs     []netip.Prefix
	RequestTags     []string
	Services        []Service
	NetInfo         *NetInfo
	SSH_HostKeys    []string
	Cloud           string
	Userspace       opt.Bool
	UserspaceRouter opt.Bool
}{})

// View returns a readonly view of NetInfo.
func (p *NetInfo) View() NetInfoView {
	return NetInfoView{ж: p}
}

// NetInfoView provides a read-only view over NetInfo.
//
// Its methods should only be called if `Valid()` returns true.
type NetInfoView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *NetInfo
}

// Valid reports whether underlying value is non-nil.
func (v NetInfoView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v NetInfoView) AsStruct() *NetInfo {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v NetInfoView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *NetInfoView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x NetInfo
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v NetInfoView) MappingVariesByDestIP() opt.Bool { return v.ж.MappingVariesByDestIP }
func (v NetInfoView) HairPinning() opt.Bool           { return v.ж.HairPinning }
func (v NetInfoView) WorkingIPv6() opt.Bool           { return v.ж.WorkingIPv6 }
func (v NetInfoView) OSHasIPv6() opt.Bool             { return v.ж.OSHasIPv6 }
func (v NetInfoView) WorkingUDP() opt.Bool            { return v.ж.WorkingUDP }
func (v NetInfoView) WorkingICMPv4() opt.Bool         { return v.ж.WorkingICMPv4 }
func (v NetInfoView) HavePortMap() bool               { return v.ж.HavePortMap }
func (v NetInfoView) UPnP() opt.Bool                  { return v.ж.UPnP }
func (v NetInfoView) PMP() opt.Bool                   { return v.ж.PMP }
func (v NetInfoView) PCP() opt.Bool                   { return v.ж.PCP }
func (v NetInfoView) PreferredDERP() int              { return v.ж.PreferredDERP }
func (v NetInfoView) LinkType() string                { return v.ж.LinkType }

func (v NetInfoView) DERPLatency() views.Map[string, float64] { return views.MapOf(v.ж.DERPLatency) }
func (v NetInfoView) String() string                          { return v.ж.String() }

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _NetInfoViewNeedsRegeneration = NetInfo(struct {
	MappingVariesByDestIP opt.Bool
	HairPinning           opt.Bool
	WorkingIPv6           opt.Bool
	OSHasIPv6             opt.Bool
	WorkingUDP            opt.Bool
	WorkingICMPv4         opt.Bool
	HavePortMap           bool
	UPnP                  opt.Bool
	PMP                   opt.Bool
	PCP                   opt.Bool
	PreferredDERP         int
	LinkType              string
	DERPLatency           map[string]float64
}{})

// View returns a readonly view of Login.
func (p *Login) View() LoginView {
	return LoginView{ж: p}
}

// LoginView provides a read-only view over Login.
//
// Its methods should only be called if `Valid()` returns true.
type LoginView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *Login
}

// Valid reports whether underlying value is non-nil.
func (v LoginView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v LoginView) AsStruct() *Login {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v LoginView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *LoginView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x Login
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v LoginView) ID() LoginID           { return v.ж.ID }
func (v LoginView) Provider() string      { return v.ж.Provider }
func (v LoginView) LoginName() string     { return v.ж.LoginName }
func (v LoginView) DisplayName() string   { return v.ж.DisplayName }
func (v LoginView) ProfilePicURL() string { return v.ж.ProfilePicURL }
func (v LoginView) Domain() string        { return v.ж.Domain }

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _LoginViewNeedsRegeneration = Login(struct {
	_             structs.Incomparable
	ID            LoginID
	Provider      string
	LoginName     string
	DisplayName   string
	ProfilePicURL string
	Domain        string
}{})

// View returns a readonly view of DNSConfig.
func (p *DNSConfig) View() DNSConfigView {
	return DNSConfigView{ж: p}
}

// DNSConfigView provides a read-only view over DNSConfig.
//
// Its methods should only be called if `Valid()` returns true.
type DNSConfigView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *DNSConfig
}

// Valid reports whether underlying value is non-nil.
func (v DNSConfigView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v DNSConfigView) AsStruct() *DNSConfig {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v DNSConfigView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *DNSConfigView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x DNSConfig
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v DNSConfigView) Resolvers() views.SliceView[*dnstype.Resolver, dnstype.ResolverView] {
	return views.SliceOfViews[*dnstype.Resolver, dnstype.ResolverView](v.ж.Resolvers)
}

func (v DNSConfigView) Routes() views.MapFn[string, []*dnstype.Resolver, views.SliceView[*dnstype.Resolver, dnstype.ResolverView]] {
	return views.MapFnOf(v.ж.Routes, func(t []*dnstype.Resolver) views.SliceView[*dnstype.Resolver, dnstype.ResolverView] {
		return views.SliceOfViews[*dnstype.Resolver, dnstype.ResolverView](t)
	})
}
func (v DNSConfigView) FallbackResolvers() views.SliceView[*dnstype.Resolver, dnstype.ResolverView] {
	return views.SliceOfViews[*dnstype.Resolver, dnstype.ResolverView](v.ж.FallbackResolvers)
}
func (v DNSConfigView) Domains() views.Slice[string]         { return views.SliceOf(v.ж.Domains) }
func (v DNSConfigView) Proxied() bool                        { return v.ж.Proxied }
func (v DNSConfigView) Nameservers() views.Slice[netip.Addr] { return views.SliceOf(v.ж.Nameservers) }
func (v DNSConfigView) CertDomains() views.Slice[string]     { return views.SliceOf(v.ж.CertDomains) }
func (v DNSConfigView) ExtraRecords() views.Slice[DNSRecord] { return views.SliceOf(v.ж.ExtraRecords) }
func (v DNSConfigView) ExitNodeFilteredSet() views.Slice[string] {
	return views.SliceOf(v.ж.ExitNodeFilteredSet)
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _DNSConfigViewNeedsRegeneration = DNSConfig(struct {
	Resolvers           []*dnstype.Resolver
	Routes              map[string][]*dnstype.Resolver
	FallbackResolvers   []*dnstype.Resolver
	Domains             []string
	Proxied             bool
	Nameservers         []netip.Addr
	CertDomains         []string
	ExtraRecords        []DNSRecord
	ExitNodeFilteredSet []string
}{})

// View returns a readonly view of RegisterResponse.
func (p *RegisterResponse) View() RegisterResponseView {
	return RegisterResponseView{ж: p}
}

// RegisterResponseView provides a read-only view over RegisterResponse.
//
// Its methods should only be called if `Valid()` returns true.
type RegisterResponseView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *RegisterResponse
}

// Valid reports whether underlying value is non-nil.
func (v RegisterResponseView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v RegisterResponseView) AsStruct() *RegisterResponse {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v RegisterResponseView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *RegisterResponseView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x RegisterResponse
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v RegisterResponseView) User() UserView           { return v.ж.User.View() }
func (v RegisterResponseView) Login() Login             { return v.ж.Login }
func (v RegisterResponseView) NodeKeyExpired() bool     { return v.ж.NodeKeyExpired }
func (v RegisterResponseView) MachineAuthorized() bool  { return v.ж.MachineAuthorized }
func (v RegisterResponseView) AuthURL() string          { return v.ж.AuthURL }
func (v RegisterResponseView) NodeKeySignature() mem.RO { return mem.B(v.ж.NodeKeySignature) }
func (v RegisterResponseView) Error() string            { return v.ж.Error }

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _RegisterResponseViewNeedsRegeneration = RegisterResponse(struct {
	User              User
	Login             Login
	NodeKeyExpired    bool
	MachineAuthorized bool
	AuthURL           string
	NodeKeySignature  tkatype.MarshaledSignature
	Error             string
}{})

// View returns a readonly view of DERPRegion.
func (p *DERPRegion) View() DERPRegionView {
	return DERPRegionView{ж: p}
}

// DERPRegionView provides a read-only view over DERPRegion.
//
// Its methods should only be called if `Valid()` returns true.
type DERPRegionView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *DERPRegion
}

// Valid reports whether underlying value is non-nil.
func (v DERPRegionView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v DERPRegionView) AsStruct() *DERPRegion {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v DERPRegionView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *DERPRegionView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x DERPRegion
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v DERPRegionView) RegionID() int      { return v.ж.RegionID }
func (v DERPRegionView) RegionCode() string { return v.ж.RegionCode }
func (v DERPRegionView) RegionName() string { return v.ж.RegionName }
func (v DERPRegionView) Avoid() bool        { return v.ж.Avoid }
func (v DERPRegionView) Nodes() views.SliceView[*DERPNode, DERPNodeView] {
	return views.SliceOfViews[*DERPNode, DERPNodeView](v.ж.Nodes)
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _DERPRegionViewNeedsRegeneration = DERPRegion(struct {
	RegionID   int
	RegionCode string
	RegionName string
	Avoid      bool
	Nodes      []*DERPNode
}{})

// View returns a readonly view of DERPMap.
func (p *DERPMap) View() DERPMapView {
	return DERPMapView{ж: p}
}

// DERPMapView provides a read-only view over DERPMap.
//
// Its methods should only be called if `Valid()` returns true.
type DERPMapView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *DERPMap
}

// Valid reports whether underlying value is non-nil.
func (v DERPMapView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v DERPMapView) AsStruct() *DERPMap {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v DERPMapView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *DERPMapView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x DERPMap
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v DERPMapView) Regions() views.MapFn[int, *DERPRegion, DERPRegionView] {
	return views.MapFnOf(v.ж.Regions, func(t *DERPRegion) DERPRegionView {
		return t.View()
	})
}
func (v DERPMapView) OmitDefaultRegions() bool { return v.ж.OmitDefaultRegions }

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _DERPMapViewNeedsRegeneration = DERPMap(struct {
	Regions            map[int]*DERPRegion
	OmitDefaultRegions bool
}{})

// View returns a readonly view of DERPNode.
func (p *DERPNode) View() DERPNodeView {
	return DERPNodeView{ж: p}
}

// DERPNodeView provides a read-only view over DERPNode.
//
// Its methods should only be called if `Valid()` returns true.
type DERPNodeView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *DERPNode
}

// Valid reports whether underlying value is non-nil.
func (v DERPNodeView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v DERPNodeView) AsStruct() *DERPNode {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v DERPNodeView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *DERPNodeView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x DERPNode
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v DERPNodeView) Name() string           { return v.ж.Name }
func (v DERPNodeView) RegionID() int          { return v.ж.RegionID }
func (v DERPNodeView) HostName() string       { return v.ж.HostName }
func (v DERPNodeView) CertName() string       { return v.ж.CertName }
func (v DERPNodeView) IPv4() string           { return v.ж.IPv4 }
func (v DERPNodeView) IPv6() string           { return v.ж.IPv6 }
func (v DERPNodeView) STUNPort() int          { return v.ж.STUNPort }
func (v DERPNodeView) STUNOnly() bool         { return v.ж.STUNOnly }
func (v DERPNodeView) DERPPort() int          { return v.ж.DERPPort }
func (v DERPNodeView) InsecureForTests() bool { return v.ж.InsecureForTests }
func (v DERPNodeView) STUNTestIP() string     { return v.ж.STUNTestIP }
func (v DERPNodeView) CanPort80() bool        { return v.ж.CanPort80 }

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _DERPNodeViewNeedsRegeneration = DERPNode(struct {
	Name             string
	RegionID         int
	HostName         string
	CertName         string
	IPv4             string
	IPv6             string
	STUNPort         int
	STUNOnly         bool
	DERPPort         int
	InsecureForTests bool
	STUNTestIP       string
	CanPort80        bool
}{})

// View returns a readonly view of SSHRule.
func (p *SSHRule) View() SSHRuleView {
	return SSHRuleView{ж: p}
}

// SSHRuleView provides a read-only view over SSHRule.
//
// Its methods should only be called if `Valid()` returns true.
type SSHRuleView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *SSHRule
}

// Valid reports whether underlying value is non-nil.
func (v SSHRuleView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v SSHRuleView) AsStruct() *SSHRule {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v SSHRuleView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *SSHRuleView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x SSHRule
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v SSHRuleView) RuleExpires() *time.Time {
	if v.ж.RuleExpires == nil {
		return nil
	}
	x := *v.ж.RuleExpires
	return &x
}

func (v SSHRuleView) Principals() views.SliceView[*SSHPrincipal, SSHPrincipalView] {
	return views.SliceOfViews[*SSHPrincipal, SSHPrincipalView](v.ж.Principals)
}

func (v SSHRuleView) SSHUsers() views.Map[string, string] { return views.MapOf(v.ж.SSHUsers) }
func (v SSHRuleView) Action() SSHActionView               { return v.ж.Action.View() }

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _SSHRuleViewNeedsRegeneration = SSHRule(struct {
	RuleExpires *time.Time
	Principals  []*SSHPrincipal
	SSHUsers    map[string]string
	Action      *SSHAction
}{})

// View returns a readonly view of SSHAction.
func (p *SSHAction) View() SSHActionView {
	return SSHActionView{ж: p}
}

// SSHActionView provides a read-only view over SSHAction.
//
// Its methods should only be called if `Valid()` returns true.
type SSHActionView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *SSHAction
}

// Valid reports whether underlying value is non-nil.
func (v SSHActionView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v SSHActionView) AsStruct() *SSHAction {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v SSHActionView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *SSHActionView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x SSHAction
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v SSHActionView) Message() string                        { return v.ж.Message }
func (v SSHActionView) Reject() bool                           { return v.ж.Reject }
func (v SSHActionView) Accept() bool                           { return v.ж.Accept }
func (v SSHActionView) SessionDuration() time.Duration         { return v.ж.SessionDuration }
func (v SSHActionView) AllowAgentForwarding() bool             { return v.ж.AllowAgentForwarding }
func (v SSHActionView) HoldAndDelegate() string                { return v.ж.HoldAndDelegate }
func (v SSHActionView) AllowLocalPortForwarding() bool         { return v.ж.AllowLocalPortForwarding }
func (v SSHActionView) AllowRemotePortForwarding() bool        { return v.ж.AllowRemotePortForwarding }
func (v SSHActionView) Recorders() views.Slice[netip.AddrPort] { return views.SliceOf(v.ж.Recorders) }
func (v SSHActionView) OnRecordingFailure() *SSHRecorderFailureAction {
	if v.ж.OnRecordingFailure == nil {
		return nil
	}
	x := *v.ж.OnRecordingFailure
	return &x
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _SSHActionViewNeedsRegeneration = SSHAction(struct {
	Message                   string
	Reject                    bool
	Accept                    bool
	SessionDuration           time.Duration
	AllowAgentForwarding      bool
	HoldAndDelegate           string
	AllowLocalPortForwarding  bool
	AllowRemotePortForwarding bool
	Recorders                 []netip.AddrPort
	OnRecordingFailure        *SSHRecorderFailureAction
}{})

// View returns a readonly view of SSHPrincipal.
func (p *SSHPrincipal) View() SSHPrincipalView {
	return SSHPrincipalView{ж: p}
}

// SSHPrincipalView provides a read-only view over SSHPrincipal.
//
// Its methods should only be called if `Valid()` returns true.
type SSHPrincipalView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *SSHPrincipal
}

// Valid reports whether underlying value is non-nil.
func (v SSHPrincipalView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v SSHPrincipalView) AsStruct() *SSHPrincipal {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v SSHPrincipalView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *SSHPrincipalView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x SSHPrincipal
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v SSHPrincipalView) Node() StableNodeID           { return v.ж.Node }
func (v SSHPrincipalView) NodeIP() string               { return v.ж.NodeIP }
func (v SSHPrincipalView) UserLogin() string            { return v.ж.UserLogin }
func (v SSHPrincipalView) Any() bool                    { return v.ж.Any }
func (v SSHPrincipalView) PubKeys() views.Slice[string] { return views.SliceOf(v.ж.PubKeys) }

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _SSHPrincipalViewNeedsRegeneration = SSHPrincipal(struct {
	Node      StableNodeID
	NodeIP    string
	UserLogin string
	Any       bool
	PubKeys   []string
}{})

// View returns a readonly view of ControlDialPlan.
func (p *ControlDialPlan) View() ControlDialPlanView {
	return ControlDialPlanView{ж: p}
}

// ControlDialPlanView provides a read-only view over ControlDialPlan.
//
// Its methods should only be called if `Valid()` returns true.
type ControlDialPlanView struct {
	// ж is the underlying mutable value, named with a hard-to-type
	// character that looks pointy like a pointer.
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *ControlDialPlan
}

// Valid reports whether underlying value is non-nil.
func (v ControlDialPlanView) Valid() bool { return v.ж != nil }

// AsStruct returns a clone of the underlying value which aliases no memory with
// the original.
func (v ControlDialPlanView) AsStruct() *ControlDialPlan {
	if v.ж == nil {
		return nil
	}
	return v.ж.Clone()
}

func (v ControlDialPlanView) MarshalJSON() ([]byte, error) { return json.Marshal(v.ж) }

func (v *ControlDialPlanView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	var x ControlDialPlan
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	v.ж = &x
	return nil
}

func (v ControlDialPlanView) Candidates() views.Slice[ControlIPCandidate] {
	return views.SliceOf(v.ж.Candidates)
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _ControlDialPlanViewNeedsRegeneration = ControlDialPlan(struct {
	Candidates []ControlIPCandidate
}{})
