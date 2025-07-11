package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/readium/cli/pkg/helpers"
	"github.com/readium/go-toolkit/pkg/analyzer"
	"github.com/readium/go-toolkit/pkg/asset"
	"github.com/readium/go-toolkit/pkg/fetcher"
	"github.com/readium/go-toolkit/pkg/manifest"
	"github.com/readium/go-toolkit/pkg/mediatype"
	"github.com/readium/go-toolkit/pkg/pub"
	"github.com/readium/go-toolkit/pkg/streamer"
	"github.com/readium/go-toolkit/pkg/util/url"
	"github.com/spf13/cobra"
)

// Indentation used to pretty-print.
var indentFlag string

// Infer accessibility metadata.
var inferA11yFlag helpers.InferA11yMetadata

// Infer the number of pages from the generated position list.
var inferPageCountFlag bool

// Ignore the given hashes when inferring textual accessibility. Hashes are in the format <algorithm>:<base64 value>, separated by commas.
var inferIgnoreImageHashesFlag []string

// Ignore the images in a given directory when inferring textual accessibility.
var inferIgnoreImageDirectoryFlag string

// Hashes to use when enhancing links, such as with image inspection. Note visual hashes are more computationally expensive. Acceptable values: sha256,md5,phash-dct,https://blurha.sh
var hash []string

// Inspect images in the manifest. Their links will be enhanced with size, width and height, and hashes
var inspectImagesFlag bool

var manifestCmd = &cobra.Command{
	Use:   "manifest <pub-path>",
	Short: "Generate a Readium Web Publication Manifest for a publication",
	Long: `Generate a Readium Web Publication Manifest for a publication.

This command will parse a publication file (such as EPUB, PDF, audiobook, etc.)
and build a Readium Web Publication Manifest for it. The JSON manifest is
printed to stdout.

Examples:
  Print out a compact JSON RWPM. 
  $ readium manifest publication.epub

  Pretty-print a JSON RWPM using two-space indent.
  $ readium manifest --indent "  " publication.epub

  Extract the publication title with ` + "`jq`" + `.
  $ readium manifest publication.epub | jq -r .metadata.title
  `,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("expects a path to the publication")
		} else if len(args) > 1 {
			return errors.New("accepts a single path to a publication")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// By the time we reach this point, we know that the arguments were
		// properly parsed, and we don't want to show the usage if an API error
		// occurs.
		cmd.SilenceUsage = true

		path, err := url.FromFilepath(filepath.Clean(args[0]))
		if err != nil {
			return fmt.Errorf("failed creating URL from filepath: %w", err)
		}

		// Images to ignore for accessibility inference
		var ignoreImagesHashes manifest.HashList
		for _, hv := range inferIgnoreImageHashesFlag {
			frags := strings.Split(hv, ":")
			if len(frags) != 2 {
				return fmt.Errorf("invalid hash algorithm: %s", hv)
			}

			var hv manifest.HashValue
			switch manifest.HashAlgorithm(strings.ToLower(frags[0])) {
			case manifest.HashAlgorithmSHA256:
				hv.Algorithm = manifest.HashAlgorithmSHA256
			case manifest.HashAlgorithmMD5:
				hv.Algorithm = manifest.HashAlgorithmMD5
			case manifest.HashAlgorithmPhashDCT:
				hv.Algorithm = manifest.HashAlgorithmPhashDCT
			default:
				return fmt.Errorf("unsupported hash algorithm: %s", frags[0])
			}
			hv.Value = frags[1]

			ignoreImagesHashes = append(ignoreImagesHashes, hv)
		}

		// Images in directory to ignore for accessibility inference
		if inferIgnoreImageDirectoryFlag != "" {
			ignoreableImageHashAlgorithms := make([]manifest.HashAlgorithm, len(hash))
			if len(hash) == 0 {
				return fmt.Errorf("no hash algorithms provided for hashing images in ignored image directory")
			}
			for i, h := range hash {
				ignoreableImageHashAlgorithms[i] = manifest.HashAlgorithm(h)
			}

			entries, err := os.ReadDir(inferIgnoreImageDirectoryFlag)
			if err != nil {
				return fmt.Errorf("failed reading directory %s: %w", inferIgnoreImageDirectoryFlag, err)
			}
			f := os.DirFS(inferIgnoreImageDirectoryFlag)
			for _, entry := range entries {
				if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
					continue
				}

				ef, err := f.Open(entry.Name())
				if err != nil {
					return fmt.Errorf("failed opening image file for hashing %s: %w", entry.Name(), err)
				}

				mt := mediatype.OfFileOnly(context.TODO(), ef)
				if mt == nil {
					return fmt.Errorf("failed determining mediatype for %s", entry.Name())
				}
				if !mt.IsImage() {
					return fmt.Errorf("file %s in ignorable image directory is not an image", entry.Name())
				}

				enhancedLink, err := analyzer.InspectImage(f, manifest.Link{
					Href:      manifest.MustNewHREFFromString(entry.Name(), false),
					MediaType: mt,
				}, ignoreableImageHashAlgorithms)
				if err != nil {
					return fmt.Errorf("failed inspecting image %s: %w", entry.Name(), err)
				}

				// Add the hashes to the list of hashes to ignore
				for _, hash := range enhancedLink.Properties.Hash() {
					already := false
					for _, v := range ignoreImagesHashes {
						if v.Equal(hash) {
							already = true
							break
						}
					}
					if already {
						continue
					}

					ignoreImagesHashes = append(ignoreImagesHashes, hash)
				}
			}
		}

		pub, err := streamer.New(streamer.Config{
			InferA11yMetadata:  streamer.InferA11yMetadata(inferA11yFlag),
			InferPageCount:     inferPageCountFlag,
			InferIgnoredImages: ignoreImagesHashes,
			OnCreatePublication: func(builder *pub.Builder) error {
				// TODO: use improved services functions when implemented
				builder.ServicesBuilder.Remove(pub.PositionsService_Name, nil)
				builder.ServicesBuilder.Remove(pub.ContentService_Name, nil)
				builder.ServicesBuilder.Remove(pub.GuidedNavigationService_Name, nil)
				return nil
			},
		}).Open(
			context.TODO(),
			asset.File(path), "",
		)
		if err != nil {
			return fmt.Errorf("failed opening %s: %w", path, err)
		}

		if inspectImagesFlag {
			hashAlgorithms := make([]manifest.HashAlgorithm, len(hash))
			for i, h := range hash {
				hashAlgorithms[i] = manifest.HashAlgorithm(h)
			}
			inspector := &helpers.ImageInspector{
				Algorithms: hashAlgorithms,
				Filesystem: fetcher.ToFS(context.TODO(), pub.Fetcher),
			}

			// Inspect publication files and overwrite the links
			pub.Manifest.ReadingOrder = pub.Manifest.ReadingOrder.Copy(inspector)
			if inspector.Error() != nil {
				return fmt.Errorf("failed inspecting images in reading order: %w", inspector.Error())
			}
			pub.Manifest.Resources = pub.Manifest.Resources.Copy(inspector)
			if inspector.Error() != nil {
				return fmt.Errorf("failed inspecting images in resources: %w", inspector.Error())
			}
		}

		var jsonBytes []byte
		if indentFlag == "" {
			jsonBytes, err = json.Marshal(pub.Manifest)
		} else {
			jsonBytes, err = json.MarshalIndent(pub.Manifest, "", indentFlag)
		}
		if err != nil {
			return fmt.Errorf("failed rendering JSON for %s: %w", path, err)
		}

		fmt.Println(string(jsonBytes))
		return err
	},
}

func init() {
	rootCmd.AddCommand(manifestCmd)
	manifestCmd.Flags().StringVarP(&indentFlag, "indent", "i", "", "Indentation used to pretty-print")
	manifestCmd.Flags().Var(&inferA11yFlag, "infer-a11y", "Infer accessibility metadata: no, merged, split")
	manifestCmd.Flags().BoolVar(&inferPageCountFlag, "infer-page-count", false, "Infer the number of pages from the generated position list.")
	manifestCmd.Flags().StringSliceVar(&hash, "hash", []string{string(manifest.HashAlgorithmSHA256)}, "Hashes to use when enhancing links, such as with image inspection. Note visual hashes are more computationally expensive. Acceptable values: sha256,md5,phash-dct,https://blurha.sh")
	manifestCmd.Flags().BoolVar(&inspectImagesFlag, "inspect-images", false, "Inspect images in the manifest. Their links will be enhanced with size, width and height, and hashes")
	manifestCmd.Flags().StringSliceVar(&inferIgnoreImageHashesFlag, "infer-a11y-ignore-image-hashes", nil, "Ignore the given hashes when inferring textual accessibility. Hashes are in the format <algorithm>:<base64 value>, separated by commas.")
	manifestCmd.Flags().StringVar(&inferIgnoreImageDirectoryFlag, "infer-a11y-ignore-image-dir", "", "Ignore the images in a given directory when inferring textual accessibility.")
}
