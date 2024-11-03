package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/auth0/go-auth0/management"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"

	"github.com/auth0/auth0-cli/internal/ansi"
)

var (
	errNoIdentitySelected = errors.New("required to select an identity")
)

type userAccountsInput struct {
	ID       string
	Identity string
}

type userIdentitySelector func(options []string) (string, error)

func userAccountsCmd(cli *cli) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "accounts",
		Short: "Manage a user's accounts",
		Long: "Manage a user's accounts. To learn more about user accounts, read " +
			"[User Account Linking](https://auth0.com/docs/manage-users/user-accounts/user-account-linking).",
	}

	cmd.SetUsageTemplate(resourceUsageTemplate())
	cmd.AddCommand(showUserAccountsCmd(cli))
	cmd.AddCommand(unlinkUserAccountCmd(cli))

	return cmd
}

func showUserAccountsCmd(cli *cli) *cobra.Command {
	var inputs userAccountsInput

	cmd := &cobra.Command{
		Use:   "show",
		Args:  cobra.MaximumNArgs(1),
		Short: "Show a user's accounts",
		Long:  "Display information about an existing user's accounts.",
		Example: `  auth0 users accounts show <user-id>
  auth0 users accounts show <user-id> --json
  auth0 users accounts show <user-id> --csv`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				if err := userID.Ask(cmd, &inputs.ID); err != nil {
					return err
				}
			} else {
				inputs.ID = args[0]
			}

			a := &management.User{ID: &inputs.ID}

			if err := ansi.Waiting(func() error {
				var err error
				a, err = cli.api.User.Read(cmd.Context(), inputs.ID)
				return err
			}); err != nil {
				return fmt.Errorf("failed to load user with ID %q: %w", inputs.ID, err)
			}

			// Display User Identities.
			cli.renderer.UserIdentityList(a.Identities)
			return nil
		},
	}

	cmd.Flags().BoolVar(&cli.json, "json", false, "Output in json format.")
	cmd.Flags().BoolVar(&cli.csv, "csv", false, "Output in csv format.")
	cmd.MarkFlagsMutuallyExclusive("json", "csv")

	return cmd
}

func unlinkUserAccountCmd(cli *cli) *cobra.Command {
	var inputs userAccountsInput

	cmd := &cobra.Command{
		Use:   "unlink",
		Args:  cobra.MaximumNArgs(2),
		Short: "Unlink account from a user",
		Long:  "Unlink an existing account from a user.",
		Example: `  auth0 users account unlink <user-id> --identity <provider|id>
  auth0 users account unlink <user-id> -i "google-oauth2|1079876542312" --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			arguments := len(args)

			if arguments == 0 {
				if err := userID.Ask(cmd, &inputs.ID); err != nil {
					return err
				}
			} else {
				inputs.ID = args[0]
			}

			if arguments < 2 {
				var err error
				if inputs.Identity, err = cli.getUserIdentity(cmd.Context(), &inputs.ID, pickUserIdentity); err != nil {
					return err
				}
			} else {
				inputs.Identity = args[1]
			}

			/*
				a := &management.User{ID: &inputs.ID}

				if err := ansi.Waiting(func() error {
					var err error
					a, err = cli.api.User.Read(cmd.Context(), inputs.ID)
					return err
				}); err != nil {
					return fmt.Errorf("failed to load user with ID %q: %w", inputs.ID, err)
				}
			*/

			//			identity := cli.getIdentity(inputs.Identity)

			//			identity.Connection = &args[0]
			return nil
		},
	}

	//	userRoles.RegisterStringSlice(cmd, &inputs.Roles, nil)
	cmd.Flags().BoolVar(&cli.json, "json", false, "Output in json format.")

	return cmd
}

func (c *cli) getIdentity(identity string) *management.UserIdentity {
	elements := strings.Split(identity, "|")
	return &management.UserIdentity{
		Provider: &elements[0],
		UserID:   &elements[1],
	}
}

func pickUserIdentity(options []string) (string, error) {
	rolesPrompt := &survey.Select{
		Message: "Identities",
		Options: options,
	}

	var selectedIdentity string
	if err := survey.AskOne(rolesPrompt, &selectedIdentity); err != nil {
		return "", err
	}

	return selectedIdentity, nil
}

func (cli *cli) getUserIdentity(ctx context.Context, userID *string, selectUserIdentity userIdentitySelector) (string, error) {
	a := &management.User{ID: userID}

	if err := ansi.Waiting(func() error {
		var err error
		a, err = cli.api.User.Read(ctx, *userID)
		return err
	}); err != nil {
		return "", fmt.Errorf("failed to load user with ID %q: %w", *userID, err)
	}

	var identities []string
	//	Ignore Primary Account Identity
	for _, identity := range a.Identities[1:] {
		identities = append(identities, *identity.Provider+"|"+*identity.UserID)
	}

	return selectUserIdentity(identities)
}
