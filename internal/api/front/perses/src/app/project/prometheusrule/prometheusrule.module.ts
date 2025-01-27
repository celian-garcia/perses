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

import { NgModule } from '@angular/core';
import { PrometheusRuleListComponent } from './prometheusrule-list/prometheusrule-list.component';
import { PrometheusRuleRoutingModule } from './prometheusrule-routing.module';
import { SharedModule } from '../../shared/shared.module';
import { MatDividerModule } from '@angular/material/divider';
import { MatExpansionModule } from '@angular/material/expansion';
import { PageModule } from '../../shared/component/page/page.module';
import { PromqlEditorComponent } from './promql-editor/promql-editor.component';

@NgModule({
  declarations: [PrometheusRuleListComponent, PromqlEditorComponent],
    imports: [
        MatDividerModule,
        MatExpansionModule,
        PrometheusRuleRoutingModule,
        SharedModule,
        PageModule,
    ]
})
export class PrometheusRuleModule {
}
