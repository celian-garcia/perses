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

package filter

import (
	"strings"
	varBuilder "github.com/perses/perses/cue/dac-utils/variable"
	labelNamesVar "github.com/perses/perses/cue/schemas/variables/prometheus-label-names:model"
)

#input: [...varBuilder]

// TODO support label arg if provided like ""\(d.label)=\"$\(d.name)\"""
filter: strings.Join(
	[for var in #input {
		[// switch
			if var.#pluginKind == _|_ {"\(var.#name)=\"$\(var.#name)\""},
			if var.#pluginKind != _|_ if var.#pluginKind != labelNamesVar.kind {"\(var.#name)=\"$\(var.#name)\""},
		][0]
	}],
	",",
	)