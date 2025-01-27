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

import { RouterModule, Routes } from '@angular/router';
import { PrometheusRuleListComponent } from './prometheusrule-list/prometheusrule-list.component';
import { NgModule } from '@angular/core';

const PROMETHEUSRULE_ROUTES: Routes = [
  {
    path: '',
    component: PrometheusRuleListComponent
  }
];

@NgModule({
  imports: [RouterModule.forChild(PROMETHEUSRULE_ROUTES)],
  exports: [RouterModule]
})
export class PrometheusRuleRoutingModule {
}
