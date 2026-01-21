// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"bytes"
	"fmt"

	"github.com/tidwall/gjson"
)

// pluginConfiguration is a type to represent an example configuration for this wasm plugin.
type pluginConfiguration struct {
	directivesMap          DirectivesMap
	metricLabels           map[string]string
	defaultDirectives      string
	perAuthorityDirectives map[string]string

	// ruleSetCacheServerCluster is the Envoy cluster address of the RuleSet Cache Server
	ruleSetCacheServerCluster string

	// ruleSetCacheServerInstance is the unique identifier used to fetch rules for this specific WAF instance
	ruleSetCacheServerInstance string

	// ruleSetReloadIntervalSeconds specifies how often to reload rules from the cache server
	ruleSetReloadIntervalSeconds int
}

type DirectivesMap map[string][]string

func parsePluginConfiguration(data []byte, infoLogger func(string)) (pluginConfiguration, error) {
	config := pluginConfiguration{}

	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return config, nil
	}

	if !gjson.ValidBytes(data) {
		return config, fmt.Errorf("invalid json: %q", data)
	}

	jsonData := gjson.ParseBytes(data)
	config.directivesMap = make(DirectivesMap)
	jsonData.Get("directives_map").ForEach(func(key, value gjson.Result) bool {
		directiveName := key.String()
		if _, ok := config.directivesMap[directiveName]; ok {
			return true
		}

		var directive []string
		value.ForEach(func(_, value gjson.Result) bool {
			directive = append(directive, value.String())
			return true
		})

		config.directivesMap[directiveName] = directive
		return true
	})

	config.metricLabels = make(map[string]string)
	jsonData.Get("metric_labels").ForEach(func(key, value gjson.Result) bool {
		config.metricLabels[key.String()] = value.String()
		return true
	})

	defaultDirectives := jsonData.Get("default_directives")
	if defaultDirectives.Exists() {
		defaultDirectivesName := defaultDirectives.String()
		if _, ok := config.directivesMap[defaultDirectivesName]; !ok {
			return config, fmt.Errorf("directive map not found for default directive: %q", defaultDirectivesName)
		}

		config.defaultDirectives = defaultDirectivesName
	}

	config.perAuthorityDirectives = make(map[string]string)
	jsonData.Get("per_authority_directives").ForEach(func(key, value gjson.Result) bool {
		config.perAuthorityDirectives[key.String()] = value.String()
		return true
	})

	for authority, directiveName := range config.perAuthorityDirectives {
		if _, ok := config.directivesMap[directiveName]; !ok {
			return config, fmt.Errorf("directive map not found for authority %s: %q", authority, directiveName)
		}
	}

	// check whether a ruleset cache server was provided to fetch rules from
	ruleSetCacheServerCluster := jsonData.Get("cache_server_cluster")
	if ruleSetCacheServerCluster.Exists() {
		config.ruleSetCacheServerCluster = ruleSetCacheServerCluster.String()
	}

	// check for a unique instance identifier, otherwise default to "default"
	ruleSetCacheServerInstance := jsonData.Get("cache_server_instance")
	if ruleSetCacheServerInstance.Exists() {
		config.ruleSetCacheServerInstance = ruleSetCacheServerInstance.String()
	} else {
		config.ruleSetCacheServerInstance = "default"
	}

	// check for a configured reload interval, otherwise default to 30 seconds
	ruleReloadInterval := jsonData.Get("rule_reload_interval_seconds")
	if ruleReloadInterval.Exists() {
		config.ruleSetReloadIntervalSeconds = int(ruleReloadInterval.Int())
	} else {
		config.ruleSetReloadIntervalSeconds = 30
	}

	if len(config.directivesMap) == 0 {
		rules := jsonData.Get("rules")

		if rules.Exists() {
			infoLogger("Defaulting to deprecated 'rules' field")

			config.defaultDirectives = "default"

			var directive []string
			rules.ForEach(func(_, value gjson.Result) bool {
				directive = append(directive, value.String())
				return true
			})
			config.directivesMap["default"] = directive
		}
	}

	return config, nil
}
