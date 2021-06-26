/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package plugin

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/credentialprovider"
	"k8s.io/kubernetes/pkg/kubelet/apis/config"
	kubeletconfig "k8s.io/kubernetes/pkg/kubelet/apis/config"
)

// readCredentialProviderConfigFile receives a path to a config file and decodes it
// into the internal CredentialProviderConfig type.
func readCredentialProviderConfigFile(configPath string) (*kubeletconfig.CredentialProviderConfig, error) {
	if configPath == "" {
		return nil, fmt.Errorf("credential provider config path is empty")
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read external registry credential provider configuration from %q: %w", configPath, err)
	}

	config, err := decode(data)
	if err != nil {
		return nil, fmt.Errorf("error decoding config %s: %w", configPath, err)
	}

	// Append current system environment variables, to the ones configured in the
	// credential provider file. Failing to do so may result in unsuccessful execution
	// of the provider binary, see https://github.com/kubernetes/kubernetes/issues/102750
	// Also, this behaviour is inline with Credential Provider Config spec
	systemEnvVars := os.Environ()
	for i := range config.Providers {
		appendSystemEnvVars(systemEnvVars, &config.Providers[i])
	}

	return config, nil
}

// decode decodes data into the internal CredentialProviderConfig type.
func decode(data []byte) (*kubeletconfig.CredentialProviderConfig, error) {
	obj, gvk, err := codecs.UniversalDecoder().Decode(data, nil, nil)
	if err != nil {
		return nil, err
	}

	if gvk.Kind != "CredentialProviderConfig" {
		return nil, fmt.Errorf("failed to decode %q (wrong Kind)", gvk.Kind)
	}

	if gvk.Group != kubeletconfig.GroupName {
		return nil, fmt.Errorf("failed to decode CredentialProviderConfig, unexpected Group: %s", gvk.Group)
	}

	if internalConfig, ok := obj.(*kubeletconfig.CredentialProviderConfig); ok {
		return internalConfig, nil
	}

	return nil, fmt.Errorf("unable to convert %T to *CredentialProviderConfig", obj)
}

// validateCredentialProviderConfig validates CredentialProviderConfig.
func validateCredentialProviderConfig(config *kubeletconfig.CredentialProviderConfig) field.ErrorList {
	allErrs := field.ErrorList{}

	if len(config.Providers) == 0 {
		allErrs = append(allErrs, field.Required(field.NewPath("providers"), "at least 1 item in plugins is required"))
	}

	fieldPath := field.NewPath("providers")
	for _, provider := range config.Providers {
		if strings.Contains(provider.Name, "/") {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("name"), provider.Name, "provider name cannot contain '/'"))
		}

		if strings.Contains(provider.Name, " ") {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("name"), provider.Name, "provider name cannot contain spaces"))
		}

		if provider.Name == "." {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("name"), provider.Name, "provider name cannot be '.'"))
		}

		if provider.Name == ".." {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("name"), provider.Name, "provider name cannot be '..'"))
		}

		if provider.APIVersion == "" {
			allErrs = append(allErrs, field.Required(fieldPath.Child("apiVersion"), "apiVersion is required"))
		} else if _, ok := apiVersions[provider.APIVersion]; !ok {
			validAPIVersions := []string{}
			for apiVersion := range apiVersions {
				validAPIVersions = append(validAPIVersions, apiVersion)
			}

			allErrs = append(allErrs, field.NotSupported(fieldPath.Child("apiVersion"), provider.APIVersion, validAPIVersions))
		}

		if len(provider.MatchImages) == 0 {
			allErrs = append(allErrs, field.Required(fieldPath.Child("matchImages"), "at least 1 item in matchImages is required"))
		}

		for _, matchImage := range provider.MatchImages {
			if _, err := credentialprovider.ParseSchemelessURL(matchImage); err != nil {
				allErrs = append(allErrs, field.Invalid(fieldPath.Child("matchImages"), matchImage, fmt.Sprintf("match image is invalid: %s", err.Error())))
			}
		}

		if provider.DefaultCacheDuration == nil {
			allErrs = append(allErrs, field.Required(fieldPath.Child("defaultCacheDuration"), "defaultCacheDuration is required"))
		}

		if provider.DefaultCacheDuration != nil && provider.DefaultCacheDuration.Duration < 0 {
			allErrs = append(allErrs, field.Invalid(fieldPath.Child("defaultCacheDuration"), provider.DefaultCacheDuration.Duration, "defaultCacheDuration must be greater than or equal to 0"))
		}
	}

	return allErrs
}

// appendSystemEnvVars appends provided array of strings of environment variables in the form of KEY=VALUE
// with the env vars present in the config
func appendSystemEnvVars(systemEnvVars []string, config *config.CredentialProvider) {
	if config == nil {
		return
	}
	configEnvVarNames := getEnvVarKeys(config.Env)
	systemEnvVarKeyValues := parseEnvVars(systemEnvVars)

	for name, value := range systemEnvVarKeyValues {
		// if an env var is supplied via provider config file then that should take
		// a higher priority than the env vars present in the OS
		if _, ok := configEnvVarNames[name]; !ok {
			config.Env = append(config.Env, kubeletconfig.ExecEnvVar{
				Name:  name,
				Value: value,
			})
		}
	}

}

// getEnvVarKeys creates a map of names of environment variables found in the
// credential config provider file for easy lookup
func getEnvVarKeys(envVars []kubeletconfig.ExecEnvVar) map[string]bool {
	namesMap := make(map[string]bool)

	for _, execEnvVar := range envVars {
		namesMap[execEnvVar.Name] = true
	}

	return namesMap
}

// parseEnvVars converts a string of environment variable of the form KEY=VALUE to a map
// some valid forms of env vars are FOO=BAR, FOO=, FOO=BARZ=BAR etc.
func parseEnvVars(envVars []string) map[string]string {
	parsedEnvVars := make(map[string]string)

	for _, pair := range envVars {
		keyValuePair := strings.SplitN(pair, "=", 2)
		if len(keyValuePair) == 2 {
			parsedEnvVars[keyValuePair[0]] = keyValuePair[1]
		} else if len(keyValuePair) == 1 {
			parsedEnvVars[keyValuePair[0]] = ""
		}
	}

	return parsedEnvVars
}
