// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        (unknown)
// source: headscale/v1/routes.proto

package v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Route struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id         uint64                 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	Node       *Node                  `protobuf:"bytes,2,opt,name=node,proto3" json:"node,omitempty"`
	Prefix     string                 `protobuf:"bytes,3,opt,name=prefix,proto3" json:"prefix,omitempty"`
	Advertised bool                   `protobuf:"varint,4,opt,name=advertised,proto3" json:"advertised,omitempty"`
	Enabled    bool                   `protobuf:"varint,5,opt,name=enabled,proto3" json:"enabled,omitempty"`
	IsPrimary  bool                   `protobuf:"varint,6,opt,name=is_primary,json=isPrimary,proto3" json:"is_primary,omitempty"`
	CreatedAt  *timestamppb.Timestamp `protobuf:"bytes,7,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	UpdatedAt  *timestamppb.Timestamp `protobuf:"bytes,8,opt,name=updated_at,json=updatedAt,proto3" json:"updated_at,omitempty"`
	DeletedAt  *timestamppb.Timestamp `protobuf:"bytes,9,opt,name=deleted_at,json=deletedAt,proto3" json:"deleted_at,omitempty"`
	Namespace  string                 `protobuf:"bytes,10,opt,name=namespace,proto3" json:"namespace,omitempty"` // __CYLONIX_MOD__
}

func (x *Route) Reset() {
	*x = Route{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_routes_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Route) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Route) ProtoMessage() {}

func (x *Route) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_routes_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Route.ProtoReflect.Descriptor instead.
func (*Route) Descriptor() ([]byte, []int) {
	return file_headscale_v1_routes_proto_rawDescGZIP(), []int{0}
}

func (x *Route) GetId() uint64 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *Route) GetNode() *Node {
	if x != nil {
		return x.Node
	}
	return nil
}

func (x *Route) GetPrefix() string {
	if x != nil {
		return x.Prefix
	}
	return ""
}

func (x *Route) GetAdvertised() bool {
	if x != nil {
		return x.Advertised
	}
	return false
}

func (x *Route) GetEnabled() bool {
	if x != nil {
		return x.Enabled
	}
	return false
}

func (x *Route) GetIsPrimary() bool {
	if x != nil {
		return x.IsPrimary
	}
	return false
}

func (x *Route) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *Route) GetUpdatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.UpdatedAt
	}
	return nil
}

func (x *Route) GetDeletedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.DeletedAt
	}
	return nil
}

func (x *Route) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

type GetRoutesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// __BEGIN_CYLONIX_MOD__
	User        *string  `protobuf:"bytes,1,opt,name=user,proto3,oneof" json:"user,omitempty"`
	NodeIdList  []uint64 `protobuf:"varint,2,rep,packed,name=node_id_list,json=nodeIdList,proto3" json:"node_id_list,omitempty"`
	Namespace   *string  `protobuf:"bytes,3,opt,name=namespace,proto3,oneof" json:"namespace,omitempty"`
	FilterBy    *string  `protobuf:"bytes,4,opt,name=filter_by,json=filterBy,proto3,oneof" json:"filter_by,omitempty"`
	FilterValue *string  `protobuf:"bytes,5,opt,name=filter_value,json=filterValue,proto3,oneof" json:"filter_value,omitempty"`
	SortBy      *string  `protobuf:"bytes,6,opt,name=sort_by,json=sortBy,proto3,oneof" json:"sort_by,omitempty"`
	SortDesc    *bool    `protobuf:"varint,7,opt,name=sort_desc,json=sortDesc,proto3,oneof" json:"sort_desc,omitempty"`
	Page        *uint32  `protobuf:"varint,8,opt,name=page,proto3,oneof" json:"page,omitempty"`
	PageSize    *uint32  `protobuf:"varint,9,opt,name=pageSize,proto3,oneof" json:"pageSize,omitempty"` // __END_CYLONIX_MOD__
}

func (x *GetRoutesRequest) Reset() {
	*x = GetRoutesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_routes_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetRoutesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetRoutesRequest) ProtoMessage() {}

func (x *GetRoutesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_routes_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetRoutesRequest.ProtoReflect.Descriptor instead.
func (*GetRoutesRequest) Descriptor() ([]byte, []int) {
	return file_headscale_v1_routes_proto_rawDescGZIP(), []int{1}
}

func (x *GetRoutesRequest) GetUser() string {
	if x != nil && x.User != nil {
		return *x.User
	}
	return ""
}

func (x *GetRoutesRequest) GetNodeIdList() []uint64 {
	if x != nil {
		return x.NodeIdList
	}
	return nil
}

func (x *GetRoutesRequest) GetNamespace() string {
	if x != nil && x.Namespace != nil {
		return *x.Namespace
	}
	return ""
}

func (x *GetRoutesRequest) GetFilterBy() string {
	if x != nil && x.FilterBy != nil {
		return *x.FilterBy
	}
	return ""
}

func (x *GetRoutesRequest) GetFilterValue() string {
	if x != nil && x.FilterValue != nil {
		return *x.FilterValue
	}
	return ""
}

func (x *GetRoutesRequest) GetSortBy() string {
	if x != nil && x.SortBy != nil {
		return *x.SortBy
	}
	return ""
}

func (x *GetRoutesRequest) GetSortDesc() bool {
	if x != nil && x.SortDesc != nil {
		return *x.SortDesc
	}
	return false
}

func (x *GetRoutesRequest) GetPage() uint32 {
	if x != nil && x.Page != nil {
		return *x.Page
	}
	return 0
}

func (x *GetRoutesRequest) GetPageSize() uint32 {
	if x != nil && x.PageSize != nil {
		return *x.PageSize
	}
	return 0
}

type GetRoutesResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Routes []*Route `protobuf:"bytes,1,rep,name=routes,proto3" json:"routes,omitempty"`
}

func (x *GetRoutesResponse) Reset() {
	*x = GetRoutesResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_routes_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetRoutesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetRoutesResponse) ProtoMessage() {}

func (x *GetRoutesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_routes_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetRoutesResponse.ProtoReflect.Descriptor instead.
func (*GetRoutesResponse) Descriptor() ([]byte, []int) {
	return file_headscale_v1_routes_proto_rawDescGZIP(), []int{2}
}

func (x *GetRoutesResponse) GetRoutes() []*Route {
	if x != nil {
		return x.Routes
	}
	return nil
}

type EnableRouteRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RouteId uint64 `protobuf:"varint,1,opt,name=route_id,json=routeId,proto3" json:"route_id,omitempty"`
}

func (x *EnableRouteRequest) Reset() {
	*x = EnableRouteRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_routes_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EnableRouteRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnableRouteRequest) ProtoMessage() {}

func (x *EnableRouteRequest) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_routes_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EnableRouteRequest.ProtoReflect.Descriptor instead.
func (*EnableRouteRequest) Descriptor() ([]byte, []int) {
	return file_headscale_v1_routes_proto_rawDescGZIP(), []int{3}
}

func (x *EnableRouteRequest) GetRouteId() uint64 {
	if x != nil {
		return x.RouteId
	}
	return 0
}

type EnableRouteResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *EnableRouteResponse) Reset() {
	*x = EnableRouteResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_routes_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EnableRouteResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnableRouteResponse) ProtoMessage() {}

func (x *EnableRouteResponse) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_routes_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EnableRouteResponse.ProtoReflect.Descriptor instead.
func (*EnableRouteResponse) Descriptor() ([]byte, []int) {
	return file_headscale_v1_routes_proto_rawDescGZIP(), []int{4}
}

type DisableRouteRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RouteId uint64 `protobuf:"varint,1,opt,name=route_id,json=routeId,proto3" json:"route_id,omitempty"`
}

func (x *DisableRouteRequest) Reset() {
	*x = DisableRouteRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_routes_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DisableRouteRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DisableRouteRequest) ProtoMessage() {}

func (x *DisableRouteRequest) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_routes_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DisableRouteRequest.ProtoReflect.Descriptor instead.
func (*DisableRouteRequest) Descriptor() ([]byte, []int) {
	return file_headscale_v1_routes_proto_rawDescGZIP(), []int{5}
}

func (x *DisableRouteRequest) GetRouteId() uint64 {
	if x != nil {
		return x.RouteId
	}
	return 0
}

type DisableRouteResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DisableRouteResponse) Reset() {
	*x = DisableRouteResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_routes_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DisableRouteResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DisableRouteResponse) ProtoMessage() {}

func (x *DisableRouteResponse) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_routes_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DisableRouteResponse.ProtoReflect.Descriptor instead.
func (*DisableRouteResponse) Descriptor() ([]byte, []int) {
	return file_headscale_v1_routes_proto_rawDescGZIP(), []int{6}
}

type GetNodeRoutesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	NodeId uint64 `protobuf:"varint,1,opt,name=node_id,json=nodeId,proto3" json:"node_id,omitempty"`
}

func (x *GetNodeRoutesRequest) Reset() {
	*x = GetNodeRoutesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_routes_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetNodeRoutesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetNodeRoutesRequest) ProtoMessage() {}

func (x *GetNodeRoutesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_routes_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetNodeRoutesRequest.ProtoReflect.Descriptor instead.
func (*GetNodeRoutesRequest) Descriptor() ([]byte, []int) {
	return file_headscale_v1_routes_proto_rawDescGZIP(), []int{7}
}

func (x *GetNodeRoutesRequest) GetNodeId() uint64 {
	if x != nil {
		return x.NodeId
	}
	return 0
}

type GetNodeRoutesResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Routes []*Route `protobuf:"bytes,1,rep,name=routes,proto3" json:"routes,omitempty"`
}

func (x *GetNodeRoutesResponse) Reset() {
	*x = GetNodeRoutesResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_routes_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetNodeRoutesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetNodeRoutesResponse) ProtoMessage() {}

func (x *GetNodeRoutesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_routes_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetNodeRoutesResponse.ProtoReflect.Descriptor instead.
func (*GetNodeRoutesResponse) Descriptor() ([]byte, []int) {
	return file_headscale_v1_routes_proto_rawDescGZIP(), []int{8}
}

func (x *GetNodeRoutesResponse) GetRoutes() []*Route {
	if x != nil {
		return x.Routes
	}
	return nil
}

type DeleteRouteRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RouteId uint64 `protobuf:"varint,1,opt,name=route_id,json=routeId,proto3" json:"route_id,omitempty"`
}

func (x *DeleteRouteRequest) Reset() {
	*x = DeleteRouteRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_routes_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteRouteRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteRouteRequest) ProtoMessage() {}

func (x *DeleteRouteRequest) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_routes_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteRouteRequest.ProtoReflect.Descriptor instead.
func (*DeleteRouteRequest) Descriptor() ([]byte, []int) {
	return file_headscale_v1_routes_proto_rawDescGZIP(), []int{9}
}

func (x *DeleteRouteRequest) GetRouteId() uint64 {
	if x != nil {
		return x.RouteId
	}
	return 0
}

type DeleteRouteResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DeleteRouteResponse) Reset() {
	*x = DeleteRouteResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_routes_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteRouteResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteRouteResponse) ProtoMessage() {}

func (x *DeleteRouteResponse) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_routes_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteRouteResponse.ProtoReflect.Descriptor instead.
func (*DeleteRouteResponse) Descriptor() ([]byte, []int) {
	return file_headscale_v1_routes_proto_rawDescGZIP(), []int{10}
}

var File_headscale_v1_routes_proto protoreflect.FileDescriptor

var file_headscale_v1_routes_proto_rawDesc = []byte{
	0x0a, 0x19, 0x68, 0x65, 0x61, 0x64, 0x73, 0x63, 0x61, 0x6c, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x72,
	0x6f, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0c, 0x68, 0x65, 0x61,
	0x64, 0x73, 0x63, 0x61, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x68, 0x65, 0x61, 0x64,
	0x73, 0x63, 0x61, 0x6c, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0xff, 0x02, 0x0a, 0x05, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x12, 0x0e, 0x0a,
	0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x02, 0x69, 0x64, 0x12, 0x26, 0x0a,
	0x04, 0x6e, 0x6f, 0x64, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x68, 0x65,
	0x61, 0x64, 0x73, 0x63, 0x61, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x52,
	0x04, 0x6e, 0x6f, 0x64, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x12, 0x1e, 0x0a,
	0x0a, 0x61, 0x64, 0x76, 0x65, 0x72, 0x74, 0x69, 0x73, 0x65, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x0a, 0x61, 0x64, 0x76, 0x65, 0x72, 0x74, 0x69, 0x73, 0x65, 0x64, 0x12, 0x18, 0x0a,
	0x07, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07,
	0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x69, 0x73, 0x5f, 0x70, 0x72,
	0x69, 0x6d, 0x61, 0x72, 0x79, 0x18, 0x06, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x69, 0x73, 0x50,
	0x72, 0x69, 0x6d, 0x61, 0x72, 0x79, 0x12, 0x39, 0x0a, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x64, 0x5f, 0x61, 0x74, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41,
	0x74, 0x12, 0x39, 0x0a, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18,
	0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x52, 0x09, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x39, 0x0a, 0x0a,
	0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x64, 0x65,
	0x6c, 0x65, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73,
	0x70, 0x61, 0x63, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65,
	0x73, 0x70, 0x61, 0x63, 0x65, 0x22, 0x9a, 0x03, 0x0a, 0x10, 0x47, 0x65, 0x74, 0x52, 0x6f, 0x75,
	0x74, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x17, 0x0a, 0x04, 0x75, 0x73,
	0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x04, 0x75, 0x73, 0x65, 0x72,
	0x88, 0x01, 0x01, 0x12, 0x20, 0x0a, 0x0c, 0x6e, 0x6f, 0x64, 0x65, 0x5f, 0x69, 0x64, 0x5f, 0x6c,
	0x69, 0x73, 0x74, 0x18, 0x02, 0x20, 0x03, 0x28, 0x04, 0x52, 0x0a, 0x6e, 0x6f, 0x64, 0x65, 0x49,
	0x64, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x21, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61,
	0x63, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x48, 0x01, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65,
	0x73, 0x70, 0x61, 0x63, 0x65, 0x88, 0x01, 0x01, 0x12, 0x20, 0x0a, 0x09, 0x66, 0x69, 0x6c, 0x74,
	0x65, 0x72, 0x5f, 0x62, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x48, 0x02, 0x52, 0x08, 0x66,
	0x69, 0x6c, 0x74, 0x65, 0x72, 0x42, 0x79, 0x88, 0x01, 0x01, 0x12, 0x26, 0x0a, 0x0c, 0x66, 0x69,
	0x6c, 0x74, 0x65, 0x72, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09,
	0x48, 0x03, 0x52, 0x0b, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x88,
	0x01, 0x01, 0x12, 0x1c, 0x0a, 0x07, 0x73, 0x6f, 0x72, 0x74, 0x5f, 0x62, 0x79, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x09, 0x48, 0x04, 0x52, 0x06, 0x73, 0x6f, 0x72, 0x74, 0x42, 0x79, 0x88, 0x01, 0x01,
	0x12, 0x20, 0x0a, 0x09, 0x73, 0x6f, 0x72, 0x74, 0x5f, 0x64, 0x65, 0x73, 0x63, 0x18, 0x07, 0x20,
	0x01, 0x28, 0x08, 0x48, 0x05, 0x52, 0x08, 0x73, 0x6f, 0x72, 0x74, 0x44, 0x65, 0x73, 0x63, 0x88,
	0x01, 0x01, 0x12, 0x17, 0x0a, 0x04, 0x70, 0x61, 0x67, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d,
	0x48, 0x06, 0x52, 0x04, 0x70, 0x61, 0x67, 0x65, 0x88, 0x01, 0x01, 0x12, 0x1f, 0x0a, 0x08, 0x70,
	0x61, 0x67, 0x65, 0x53, 0x69, 0x7a, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0d, 0x48, 0x07, 0x52,
	0x08, 0x70, 0x61, 0x67, 0x65, 0x53, 0x69, 0x7a, 0x65, 0x88, 0x01, 0x01, 0x42, 0x07, 0x0a, 0x05,
	0x5f, 0x75, 0x73, 0x65, 0x72, 0x42, 0x0c, 0x0a, 0x0a, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70,
	0x61, 0x63, 0x65, 0x42, 0x0c, 0x0a, 0x0a, 0x5f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x5f, 0x62,
	0x79, 0x42, 0x0f, 0x0a, 0x0d, 0x5f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x5f, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x42, 0x0a, 0x0a, 0x08, 0x5f, 0x73, 0x6f, 0x72, 0x74, 0x5f, 0x62, 0x79, 0x42, 0x0c,
	0x0a, 0x0a, 0x5f, 0x73, 0x6f, 0x72, 0x74, 0x5f, 0x64, 0x65, 0x73, 0x63, 0x42, 0x07, 0x0a, 0x05,
	0x5f, 0x70, 0x61, 0x67, 0x65, 0x42, 0x0b, 0x0a, 0x09, 0x5f, 0x70, 0x61, 0x67, 0x65, 0x53, 0x69,
	0x7a, 0x65, 0x22, 0x40, 0x0a, 0x11, 0x47, 0x65, 0x74, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2b, 0x0a, 0x06, 0x72, 0x6f, 0x75, 0x74, 0x65,
	0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x73, 0x63,
	0x61, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x52, 0x06, 0x72, 0x6f,
	0x75, 0x74, 0x65, 0x73, 0x22, 0x2f, 0x0a, 0x12, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x52, 0x6f,
	0x75, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x19, 0x0a, 0x08, 0x72, 0x6f,
	0x75, 0x74, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x72, 0x6f,
	0x75, 0x74, 0x65, 0x49, 0x64, 0x22, 0x15, 0x0a, 0x13, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x52,
	0x6f, 0x75, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x30, 0x0a, 0x13,
	0x44, 0x69, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x19, 0x0a, 0x08, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x5f, 0x69, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x49, 0x64, 0x22, 0x16,
	0x0a, 0x14, 0x44, 0x69, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x2f, 0x0a, 0x14, 0x47, 0x65, 0x74, 0x4e, 0x6f, 0x64,
	0x65, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x17,
	0x0a, 0x07, 0x6e, 0x6f, 0x64, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x06, 0x6e, 0x6f, 0x64, 0x65, 0x49, 0x64, 0x22, 0x44, 0x0a, 0x15, 0x47, 0x65, 0x74, 0x4e, 0x6f,
	0x64, 0x65, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x2b, 0x0a, 0x06, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x13, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x73, 0x63, 0x61, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x2e,
	0x52, 0x6f, 0x75, 0x74, 0x65, 0x52, 0x06, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x22, 0x2f, 0x0a,
	0x12, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x19, 0x0a, 0x08, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x5f, 0x69, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x49, 0x64, 0x22, 0x15,
	0x0a, 0x13, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x29, 0x5a, 0x27, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x6a, 0x75, 0x61, 0x6e, 0x66, 0x6f, 0x6e, 0x74, 0x2f, 0x68, 0x65, 0x61,
	0x64, 0x73, 0x63, 0x61, 0x6c, 0x65, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x67, 0x6f, 0x2f, 0x76, 0x31,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_headscale_v1_routes_proto_rawDescOnce sync.Once
	file_headscale_v1_routes_proto_rawDescData = file_headscale_v1_routes_proto_rawDesc
)

func file_headscale_v1_routes_proto_rawDescGZIP() []byte {
	file_headscale_v1_routes_proto_rawDescOnce.Do(func() {
		file_headscale_v1_routes_proto_rawDescData = protoimpl.X.CompressGZIP(file_headscale_v1_routes_proto_rawDescData)
	})
	return file_headscale_v1_routes_proto_rawDescData
}

var file_headscale_v1_routes_proto_msgTypes = make([]protoimpl.MessageInfo, 11)
var file_headscale_v1_routes_proto_goTypes = []any{
	(*Route)(nil),                 // 0: headscale.v1.Route
	(*GetRoutesRequest)(nil),      // 1: headscale.v1.GetRoutesRequest
	(*GetRoutesResponse)(nil),     // 2: headscale.v1.GetRoutesResponse
	(*EnableRouteRequest)(nil),    // 3: headscale.v1.EnableRouteRequest
	(*EnableRouteResponse)(nil),   // 4: headscale.v1.EnableRouteResponse
	(*DisableRouteRequest)(nil),   // 5: headscale.v1.DisableRouteRequest
	(*DisableRouteResponse)(nil),  // 6: headscale.v1.DisableRouteResponse
	(*GetNodeRoutesRequest)(nil),  // 7: headscale.v1.GetNodeRoutesRequest
	(*GetNodeRoutesResponse)(nil), // 8: headscale.v1.GetNodeRoutesResponse
	(*DeleteRouteRequest)(nil),    // 9: headscale.v1.DeleteRouteRequest
	(*DeleteRouteResponse)(nil),   // 10: headscale.v1.DeleteRouteResponse
	(*Node)(nil),                  // 11: headscale.v1.Node
	(*timestamppb.Timestamp)(nil), // 12: google.protobuf.Timestamp
}
var file_headscale_v1_routes_proto_depIdxs = []int32{
	11, // 0: headscale.v1.Route.node:type_name -> headscale.v1.Node
	12, // 1: headscale.v1.Route.created_at:type_name -> google.protobuf.Timestamp
	12, // 2: headscale.v1.Route.updated_at:type_name -> google.protobuf.Timestamp
	12, // 3: headscale.v1.Route.deleted_at:type_name -> google.protobuf.Timestamp
	0,  // 4: headscale.v1.GetRoutesResponse.routes:type_name -> headscale.v1.Route
	0,  // 5: headscale.v1.GetNodeRoutesResponse.routes:type_name -> headscale.v1.Route
	6,  // [6:6] is the sub-list for method output_type
	6,  // [6:6] is the sub-list for method input_type
	6,  // [6:6] is the sub-list for extension type_name
	6,  // [6:6] is the sub-list for extension extendee
	0,  // [0:6] is the sub-list for field type_name
}

func init() { file_headscale_v1_routes_proto_init() }
func file_headscale_v1_routes_proto_init() {
	if File_headscale_v1_routes_proto != nil {
		return
	}
	file_headscale_v1_node_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_headscale_v1_routes_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*Route); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_headscale_v1_routes_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*GetRoutesRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_headscale_v1_routes_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*GetRoutesResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_headscale_v1_routes_proto_msgTypes[3].Exporter = func(v any, i int) any {
			switch v := v.(*EnableRouteRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_headscale_v1_routes_proto_msgTypes[4].Exporter = func(v any, i int) any {
			switch v := v.(*EnableRouteResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_headscale_v1_routes_proto_msgTypes[5].Exporter = func(v any, i int) any {
			switch v := v.(*DisableRouteRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_headscale_v1_routes_proto_msgTypes[6].Exporter = func(v any, i int) any {
			switch v := v.(*DisableRouteResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_headscale_v1_routes_proto_msgTypes[7].Exporter = func(v any, i int) any {
			switch v := v.(*GetNodeRoutesRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_headscale_v1_routes_proto_msgTypes[8].Exporter = func(v any, i int) any {
			switch v := v.(*GetNodeRoutesResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_headscale_v1_routes_proto_msgTypes[9].Exporter = func(v any, i int) any {
			switch v := v.(*DeleteRouteRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_headscale_v1_routes_proto_msgTypes[10].Exporter = func(v any, i int) any {
			switch v := v.(*DeleteRouteResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_headscale_v1_routes_proto_msgTypes[1].OneofWrappers = []any{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_headscale_v1_routes_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   11,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_headscale_v1_routes_proto_goTypes,
		DependencyIndexes: file_headscale_v1_routes_proto_depIdxs,
		MessageInfos:      file_headscale_v1_routes_proto_msgTypes,
	}.Build()
	File_headscale_v1_routes_proto = out.File
	file_headscale_v1_routes_proto_rawDesc = nil
	file_headscale_v1_routes_proto_goTypes = nil
	file_headscale_v1_routes_proto_depIdxs = nil
}
