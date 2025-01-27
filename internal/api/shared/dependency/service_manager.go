// Copyright 2021 Amadeus s.a.s
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

// Package dependency provides different manager that will be used to instantiate the different services and daos of the API.
// It's one way to inject the different dependencies into the different services/daos.
package dependency

import (
	dashboardImpl "github.com/perses/perses/internal/api/impl/v1/dashboard"
	dashboardFeedimpl "github.com/perses/perses/internal/api/impl/v1/dashboard_feed"
	datasourceImpl "github.com/perses/perses/internal/api/impl/v1/datasource"
	projectImpl "github.com/perses/perses/internal/api/impl/v1/project"
	prometheusruleImpl "github.com/perses/perses/internal/api/impl/v1/prometheusrule"
	userImpl "github.com/perses/perses/internal/api/impl/v1/user"
	"github.com/perses/perses/internal/api/interface/v1/dashboard"
	"github.com/perses/perses/internal/api/interface/v1/dashboard_feed"
	"github.com/perses/perses/internal/api/interface/v1/datasource"
	"github.com/perses/perses/internal/api/interface/v1/project"
	"github.com/perses/perses/internal/api/interface/v1/prometheusrule"
	"github.com/perses/perses/internal/api/interface/v1/user"
)

type ServiceManager interface {
	GetDashboard() dashboard.Service
	GetDashboardFeed() dashboard_feed.Service
	GetDatasource() datasource.Service
	GetProject() project.Service
	GetPrometheusRule() prometheusrule.Service
	GetUser() user.Service
}

type service struct {
	ServiceManager
	dashboard      dashboard.Service
	dashboardFeed  dashboard_feed.Service
	datasource     datasource.Service
	project        project.Service
	prometheusRule prometheusrule.Service
	user           user.Service
}

func NewServiceManager(dao PersistenceManager) ServiceManager {
	dashboardService := dashboardImpl.NewService(dao.GetDashboard())
	datasourceService := datasourceImpl.NewService(dao.GetDatasource())
	dashboardFeedService := dashboardFeedimpl.NewService(datasourceService)
	projectService := projectImpl.NewService(dao.GetProject())
	prometheusRuleService := prometheusruleImpl.NewService(dao.GetPrometheusRule())
	userService := userImpl.NewService(dao.GetUser())
	return &service{
		dashboard:      dashboardService,
		dashboardFeed:  dashboardFeedService,
		datasource:     datasourceService,
		project:        projectService,
		prometheusRule: prometheusRuleService,
		user:           userService,
	}
}

func (s *service) GetDashboard() dashboard.Service {
	return s.dashboard
}

func (s *service) GetDashboardFeed() dashboard_feed.Service {
	return s.dashboardFeed
}

func (s *service) GetDatasource() datasource.Service {
	return s.datasource
}

func (s *service) GetProject() project.Service {
	return s.project
}

func (s *service) GetPrometheusRule() prometheusrule.Service {
	return s.prometheusRule
}

func (s *service) GetUser() user.Service {
	return s.user
}
