// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        (unknown)
// source: headscale/v1/user.proto

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

type User struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id        string                 `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name      string                 `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	CreatedAt *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	Namespace string                 `protobuf:"bytes,4,opt,name=namespace,proto3" json:"namespace,omitempty"` // __CYLONIX_MOD__
}

func (x *User) Reset() {
	*x = User{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_user_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *User) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*User) ProtoMessage() {}

func (x *User) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_user_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use User.ProtoReflect.Descriptor instead.
func (*User) Descriptor() ([]byte, []int) {
	return file_headscale_v1_user_proto_rawDescGZIP(), []int{0}
}

func (x *User) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *User) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *User) GetCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CreatedAt
	}
	return nil
}

func (x *User) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

type GetUserRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *GetUserRequest) Reset() {
	*x = GetUserRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_user_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetUserRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetUserRequest) ProtoMessage() {}

func (x *GetUserRequest) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_user_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetUserRequest.ProtoReflect.Descriptor instead.
func (*GetUserRequest) Descriptor() ([]byte, []int) {
	return file_headscale_v1_user_proto_rawDescGZIP(), []int{1}
}

func (x *GetUserRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type GetUserResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	User *User `protobuf:"bytes,1,opt,name=user,proto3" json:"user,omitempty"`
}

func (x *GetUserResponse) Reset() {
	*x = GetUserResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_user_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetUserResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetUserResponse) ProtoMessage() {}

func (x *GetUserResponse) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_user_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetUserResponse.ProtoReflect.Descriptor instead.
func (*GetUserResponse) Descriptor() ([]byte, []int) {
	return file_headscale_v1_user_proto_rawDescGZIP(), []int{2}
}

func (x *GetUserResponse) GetUser() *User {
	if x != nil {
		return x.User
	}
	return nil
}

type CreateUserRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name      string  `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Namespace *string `protobuf:"bytes,2,opt,name=namespace,proto3,oneof" json:"namespace,omitempty"` // __CYLONIX_MOD__
}

func (x *CreateUserRequest) Reset() {
	*x = CreateUserRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_user_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateUserRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateUserRequest) ProtoMessage() {}

func (x *CreateUserRequest) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_user_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateUserRequest.ProtoReflect.Descriptor instead.
func (*CreateUserRequest) Descriptor() ([]byte, []int) {
	return file_headscale_v1_user_proto_rawDescGZIP(), []int{3}
}

func (x *CreateUserRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *CreateUserRequest) GetNamespace() string {
	if x != nil && x.Namespace != nil {
		return *x.Namespace
	}
	return ""
}

type CreateUserResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	User *User `protobuf:"bytes,1,opt,name=user,proto3" json:"user,omitempty"`
}

func (x *CreateUserResponse) Reset() {
	*x = CreateUserResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_user_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateUserResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateUserResponse) ProtoMessage() {}

func (x *CreateUserResponse) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_user_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateUserResponse.ProtoReflect.Descriptor instead.
func (*CreateUserResponse) Descriptor() ([]byte, []int) {
	return file_headscale_v1_user_proto_rawDescGZIP(), []int{4}
}

func (x *CreateUserResponse) GetUser() *User {
	if x != nil {
		return x.User
	}
	return nil
}

type RenameUserRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	OldName string `protobuf:"bytes,1,opt,name=old_name,json=oldName,proto3" json:"old_name,omitempty"`
	NewName string `protobuf:"bytes,2,opt,name=new_name,json=newName,proto3" json:"new_name,omitempty"`
}

func (x *RenameUserRequest) Reset() {
	*x = RenameUserRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_user_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RenameUserRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RenameUserRequest) ProtoMessage() {}

func (x *RenameUserRequest) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_user_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RenameUserRequest.ProtoReflect.Descriptor instead.
func (*RenameUserRequest) Descriptor() ([]byte, []int) {
	return file_headscale_v1_user_proto_rawDescGZIP(), []int{5}
}

func (x *RenameUserRequest) GetOldName() string {
	if x != nil {
		return x.OldName
	}
	return ""
}

func (x *RenameUserRequest) GetNewName() string {
	if x != nil {
		return x.NewName
	}
	return ""
}

type RenameUserResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	User *User `protobuf:"bytes,1,opt,name=user,proto3" json:"user,omitempty"`
}

func (x *RenameUserResponse) Reset() {
	*x = RenameUserResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_user_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RenameUserResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RenameUserResponse) ProtoMessage() {}

func (x *RenameUserResponse) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_user_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RenameUserResponse.ProtoReflect.Descriptor instead.
func (*RenameUserResponse) Descriptor() ([]byte, []int) {
	return file_headscale_v1_user_proto_rawDescGZIP(), []int{6}
}

func (x *RenameUserResponse) GetUser() *User {
	if x != nil {
		return x.User
	}
	return nil
}

type DeleteUserRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *DeleteUserRequest) Reset() {
	*x = DeleteUserRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_user_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteUserRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteUserRequest) ProtoMessage() {}

func (x *DeleteUserRequest) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_user_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteUserRequest.ProtoReflect.Descriptor instead.
func (*DeleteUserRequest) Descriptor() ([]byte, []int) {
	return file_headscale_v1_user_proto_rawDescGZIP(), []int{7}
}

func (x *DeleteUserRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type DeleteUserResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DeleteUserResponse) Reset() {
	*x = DeleteUserResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_user_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteUserResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteUserResponse) ProtoMessage() {}

func (x *DeleteUserResponse) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_user_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteUserResponse.ProtoReflect.Descriptor instead.
func (*DeleteUserResponse) Descriptor() ([]byte, []int) {
	return file_headscale_v1_user_proto_rawDescGZIP(), []int{8}
}

type ListUsersRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *ListUsersRequest) Reset() {
	*x = ListUsersRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_user_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListUsersRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListUsersRequest) ProtoMessage() {}

func (x *ListUsersRequest) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_user_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListUsersRequest.ProtoReflect.Descriptor instead.
func (*ListUsersRequest) Descriptor() ([]byte, []int) {
	return file_headscale_v1_user_proto_rawDescGZIP(), []int{9}
}

type ListUsersResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Users []*User `protobuf:"bytes,1,rep,name=users,proto3" json:"users,omitempty"`
}

func (x *ListUsersResponse) Reset() {
	*x = ListUsersResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_headscale_v1_user_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListUsersResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListUsersResponse) ProtoMessage() {}

func (x *ListUsersResponse) ProtoReflect() protoreflect.Message {
	mi := &file_headscale_v1_user_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListUsersResponse.ProtoReflect.Descriptor instead.
func (*ListUsersResponse) Descriptor() ([]byte, []int) {
	return file_headscale_v1_user_proto_rawDescGZIP(), []int{10}
}

func (x *ListUsersResponse) GetUsers() []*User {
	if x != nil {
		return x.Users
	}
	return nil
}

var File_headscale_v1_user_proto protoreflect.FileDescriptor

var file_headscale_v1_user_proto_rawDesc = []byte{
	0x0a, 0x17, 0x68, 0x65, 0x61, 0x64, 0x73, 0x63, 0x61, 0x6c, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x75,
	0x73, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0c, 0x68, 0x65, 0x61, 0x64, 0x73,
	0x63, 0x61, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x83, 0x01, 0x0a, 0x04, 0x55, 0x73, 0x65,
	0x72, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69,
	0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x39, 0x0a, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64,
	0x5f, 0x61, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74,
	0x12, 0x1c, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x22, 0x24,
	0x0a, 0x0e, 0x47, 0x65, 0x74, 0x55, 0x73, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x22, 0x39, 0x0a, 0x0f, 0x47, 0x65, 0x74, 0x55, 0x73, 0x65, 0x72, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x26, 0x0a, 0x04, 0x75, 0x73, 0x65, 0x72, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x73, 0x63, 0x61, 0x6c,
	0x65, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x52, 0x04, 0x75, 0x73, 0x65, 0x72, 0x22,
	0x58, 0x0a, 0x11, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x55, 0x73, 0x65, 0x72, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x21, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65,
	0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x09, 0x6e,
	0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x88, 0x01, 0x01, 0x42, 0x0c, 0x0a, 0x0a, 0x5f,
	0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x22, 0x3c, 0x0a, 0x12, 0x43, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x55, 0x73, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x26, 0x0a, 0x04, 0x75, 0x73, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e,
	0x68, 0x65, 0x61, 0x64, 0x73, 0x63, 0x61, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x73, 0x65,
	0x72, 0x52, 0x04, 0x75, 0x73, 0x65, 0x72, 0x22, 0x49, 0x0a, 0x11, 0x52, 0x65, 0x6e, 0x61, 0x6d,
	0x65, 0x55, 0x73, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x19, 0x0a, 0x08,
	0x6f, 0x6c, 0x64, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07,
	0x6f, 0x6c, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x6e, 0x65, 0x77, 0x5f, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6e, 0x65, 0x77, 0x4e, 0x61,
	0x6d, 0x65, 0x22, 0x3c, 0x0a, 0x12, 0x52, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x55, 0x73, 0x65, 0x72,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x26, 0x0a, 0x04, 0x75, 0x73, 0x65, 0x72,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x73, 0x63, 0x61,
	0x6c, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x52, 0x04, 0x75, 0x73, 0x65, 0x72,
	0x22, 0x27, 0x0a, 0x11, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x55, 0x73, 0x65, 0x72, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x14, 0x0a, 0x12, 0x44, 0x65, 0x6c,
	0x65, 0x74, 0x65, 0x55, 0x73, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22,
	0x12, 0x0a, 0x10, 0x4c, 0x69, 0x73, 0x74, 0x55, 0x73, 0x65, 0x72, 0x73, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x22, 0x3d, 0x0a, 0x11, 0x4c, 0x69, 0x73, 0x74, 0x55, 0x73, 0x65, 0x72, 0x73,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x28, 0x0a, 0x05, 0x75, 0x73, 0x65, 0x72,
	0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x73, 0x63,
	0x61, 0x6c, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x52, 0x05, 0x75, 0x73, 0x65,
	0x72, 0x73, 0x42, 0x29, 0x5a, 0x27, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x6a, 0x75, 0x61, 0x6e, 0x66, 0x6f, 0x6e, 0x74, 0x2f, 0x68, 0x65, 0x61, 0x64, 0x73, 0x63,
	0x61, 0x6c, 0x65, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x67, 0x6f, 0x2f, 0x76, 0x31, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_headscale_v1_user_proto_rawDescOnce sync.Once
	file_headscale_v1_user_proto_rawDescData = file_headscale_v1_user_proto_rawDesc
)

func file_headscale_v1_user_proto_rawDescGZIP() []byte {
	file_headscale_v1_user_proto_rawDescOnce.Do(func() {
		file_headscale_v1_user_proto_rawDescData = protoimpl.X.CompressGZIP(file_headscale_v1_user_proto_rawDescData)
	})
	return file_headscale_v1_user_proto_rawDescData
}

var file_headscale_v1_user_proto_msgTypes = make([]protoimpl.MessageInfo, 11)
var file_headscale_v1_user_proto_goTypes = []any{
	(*User)(nil),                  // 0: headscale.v1.User
	(*GetUserRequest)(nil),        // 1: headscale.v1.GetUserRequest
	(*GetUserResponse)(nil),       // 2: headscale.v1.GetUserResponse
	(*CreateUserRequest)(nil),     // 3: headscale.v1.CreateUserRequest
	(*CreateUserResponse)(nil),    // 4: headscale.v1.CreateUserResponse
	(*RenameUserRequest)(nil),     // 5: headscale.v1.RenameUserRequest
	(*RenameUserResponse)(nil),    // 6: headscale.v1.RenameUserResponse
	(*DeleteUserRequest)(nil),     // 7: headscale.v1.DeleteUserRequest
	(*DeleteUserResponse)(nil),    // 8: headscale.v1.DeleteUserResponse
	(*ListUsersRequest)(nil),      // 9: headscale.v1.ListUsersRequest
	(*ListUsersResponse)(nil),     // 10: headscale.v1.ListUsersResponse
	(*timestamppb.Timestamp)(nil), // 11: google.protobuf.Timestamp
}
var file_headscale_v1_user_proto_depIdxs = []int32{
	11, // 0: headscale.v1.User.created_at:type_name -> google.protobuf.Timestamp
	0,  // 1: headscale.v1.GetUserResponse.user:type_name -> headscale.v1.User
	0,  // 2: headscale.v1.CreateUserResponse.user:type_name -> headscale.v1.User
	0,  // 3: headscale.v1.RenameUserResponse.user:type_name -> headscale.v1.User
	0,  // 4: headscale.v1.ListUsersResponse.users:type_name -> headscale.v1.User
	5,  // [5:5] is the sub-list for method output_type
	5,  // [5:5] is the sub-list for method input_type
	5,  // [5:5] is the sub-list for extension type_name
	5,  // [5:5] is the sub-list for extension extendee
	0,  // [0:5] is the sub-list for field type_name
}

func init() { file_headscale_v1_user_proto_init() }
func file_headscale_v1_user_proto_init() {
	if File_headscale_v1_user_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_headscale_v1_user_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*User); i {
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
		file_headscale_v1_user_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*GetUserRequest); i {
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
		file_headscale_v1_user_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*GetUserResponse); i {
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
		file_headscale_v1_user_proto_msgTypes[3].Exporter = func(v any, i int) any {
			switch v := v.(*CreateUserRequest); i {
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
		file_headscale_v1_user_proto_msgTypes[4].Exporter = func(v any, i int) any {
			switch v := v.(*CreateUserResponse); i {
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
		file_headscale_v1_user_proto_msgTypes[5].Exporter = func(v any, i int) any {
			switch v := v.(*RenameUserRequest); i {
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
		file_headscale_v1_user_proto_msgTypes[6].Exporter = func(v any, i int) any {
			switch v := v.(*RenameUserResponse); i {
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
		file_headscale_v1_user_proto_msgTypes[7].Exporter = func(v any, i int) any {
			switch v := v.(*DeleteUserRequest); i {
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
		file_headscale_v1_user_proto_msgTypes[8].Exporter = func(v any, i int) any {
			switch v := v.(*DeleteUserResponse); i {
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
		file_headscale_v1_user_proto_msgTypes[9].Exporter = func(v any, i int) any {
			switch v := v.(*ListUsersRequest); i {
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
		file_headscale_v1_user_proto_msgTypes[10].Exporter = func(v any, i int) any {
			switch v := v.(*ListUsersResponse); i {
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
	file_headscale_v1_user_proto_msgTypes[3].OneofWrappers = []any{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_headscale_v1_user_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   11,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_headscale_v1_user_proto_goTypes,
		DependencyIndexes: file_headscale_v1_user_proto_depIdxs,
		MessageInfos:      file_headscale_v1_user_proto_msgTypes,
	}.Build()
	File_headscale_v1_user_proto = out.File
	file_headscale_v1_user_proto_rawDesc = nil
	file_headscale_v1_user_proto_goTypes = nil
	file_headscale_v1_user_proto_depIdxs = nil
}
