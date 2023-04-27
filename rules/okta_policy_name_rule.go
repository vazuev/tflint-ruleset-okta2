package rules

import (
	"fmt"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/logger"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// OktaPolicyNameRule checks whether ...
type OktaPolicyNameRule struct {
	resourceType  string
	attributeName string
	max           int
	min           int
}

// NewOktaPolicyNameRule returns a new rule
func NewOktaPolicyNameRule() *OktaPolicyNameRule {
	return &OktaPolicyNameRule{
		resourceType:  "okta_auth_server_policy",
		attributeName: "name",
		max:           50,
		min:           1,
	}
}

// Name returns the rule name
func (r *OktaPolicyNameRule) Name() string {
	return "okta_policy_name_rule"
}

// Enabled returns whether the rule is enabled by default
func (r *OktaPolicyNameRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *OktaPolicyNameRule) Severity() tflint.Severity {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *OktaPolicyNameRule) Link() string {
	return ""
}

// Check checks whether ...
func (r *OktaPolicyNameRule) Check(runner tflint.Runner) error {
	log.Printf("[TRACE] Check `%s` rule", r.Name())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val, nil)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssueOnExpr(
					r,
					"Name must be from 1 to 50 characters",
					attribute.Expr,
				)
			}
			if len(val) < r.min {
				runner.EmitIssueOnExpr(
					r,
					"Name must be from 1 to 50 characters",
					attribute.Expr,
				)
			}
			return nil
		})
	})
}
