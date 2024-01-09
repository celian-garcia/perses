// Copyright 2024 The Perses Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"strings"

	"github.com/perses/perses/internal/api/interface/v1/user"
	databaseModel "github.com/perses/perses/internal/api/shared/database/model"
	v1 "github.com/perses/perses/pkg/model/api/v1"
)

// externalUserInfoProfile is a subset of oidc.UserInfoProfile structure with only the interesting information.
type externalUserInfoProfile struct {
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	MiddleName        string `json:"middle_name,omitempty"`
	Nickname          string `json:"nickname,omitempty"`
	Profile           string `json:"profile,omitempty"`
	Picture           string `json:"picture,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
}

// externalUserInfo defines the way to build user info which is different according to each provider kind.
type externalUserInfo interface {
	// GetLogin returns the login designating the ``metadata.name`` of the user entity.
	GetLogin() string
	// GetProfile returns various user information that may be set in the ``specs`` of the user entity.
	GetProfile() externalUserInfoProfile
	// GetIssuer returns the provider issuer. It identifies the external provider used to collect this user information.
	GetIssuer() string
}

func buildLoginFromEmail(email string) string {
	return strings.Split(email, "@")[0]
}

type service struct {
	dao user.DAO
}

func arbitrate(old, new string) string {
	if len(new) > 0 {
		return new
	}
	return old
}

func saveProfileInfo(specs v1.UserSpec, uInfoProfile externalUserInfoProfile) v1.UserSpec {
	specs.FirstName = arbitrate(specs.FirstName, uInfoProfile.GivenName)
	specs.LastName = arbitrate(specs.LastName, uInfoProfile.FamilyName)
	return specs
}

func (s *service) getOrPrepareUserEntity(login string) (*v1.User, bool, error) {
	result, err := s.dao.Get(login)
	if err != nil {
		if databaseModel.IsKeyNotFound(err) {
			result = &v1.User{Kind: v1.KindUser, Metadata: v1.Metadata{Name: login}}
			return result, true, nil
		}
		return nil, false, err
	}
	return result, false, nil
}

func (s *service) SyncUser(uInfo externalUserInfo) (*v1.User, error) {
	entity, isNew, err := s.getOrPrepareUserEntity(uInfo.GetLogin())
	if err != nil {
		return nil, err
	}

	entity.Spec = saveProfileInfo(entity.Spec, uInfo.GetProfile())

	if isNew {
		entity.Metadata.CreateNow()
		err = s.dao.Create(entity)
		if err != nil {
			return nil, err
		}
	}

	entity.Metadata.Update(entity.Metadata)
	err = s.dao.Update(entity)
	if err != nil {
		return nil, err
	}
	return entity, nil

}
