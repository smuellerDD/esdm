# Build the ESDM documentation from its Typst sources.
#
#   make                  the design document and the slide deck as PDF
#   make figures          only render the draw.io and PlantUML figures to SVG
#   make diff REV=<rev>   both documents with the changes since git revision
#                         <rev> marked: esdm-diff.pdf, esdm_presentation-diff.pdf
#   make clean
#
# Needs typst, plantuml and drawio (run under xvfb-run when there is no
# display; drawio-headless of nixpkgs does that on its own), and for the
# diff git and python3. With all of these and the fonts from nixpkgs:
#
#   nix build .#esdm-doc                  the PDFs
#   nix run .#esdm-doc-diff -- <rev>      make diff REV=<rev>
#   nix develop .#doc                     a shell to run make in
#
# A Typst warning fails the build. The documents are written to OUT (this
# directory by default), the trees make diff compares to BUILD. The SVGs of
# the figures are rendered next to their sources and are not tracked by
# git.

TYPST ?= typst
PLANTUML ?= plantuml
PYTHON ?= python3
GIT ?= git
ifeq ($(DISPLAY)$(WAYLAND_DISPLAY),)
DRAWIO ?= xvfb-run -a drawio
else
DRAWIO ?= drawio
endif

# The light theme gives fixed colours instead of CSS light-dark() ones. The
# sources use plain (html=0) labels, as Typst does not render the
# foreignObject of HTML labels.
DRAWIO_FLAGS ?= -x -f svg --theme light --embed-svg-fonts false -b 1

OUT ?= .
BUILD ?= build

# Every drawio and plantuml run is a process of its own that takes seconds
# to start: render the figures side by side, on all CPUs unless make was
# given -j. drawio-headless gives each run an X display and a configuration
# directory of its own, so they do not get in each other's way.
ifeq ($(filter -j%,$(MAKEFLAGS)),)
MAKEFLAGS += -j$(shell nproc 2>/dev/null || echo 4)
endif
MAKEFLAGS += --output-sync=target

# The revision make diff compares with, and how the diff names both
# versions: the old one by REV (a doc-<version> tag by its version), the new
# one by the version in meson.build.
REV ?= $(error set REV to the git revision to compare with: make diff REV=<rev>)
LABEL_OLD ?= $(patsubst doc-%,%,$(REV))
LABEL_NEW ?= $(shell sed -n "s/^[[:space:]]*version: '\(.*\)',/\1/p" \
	../../meson.build 2>/dev/null | head -n 1)

DOCS := esdm esdm_presentation
esdm_SRC := esdm.typ
esdm_presentation_SRC := presentations/esdm_presentation.typ

# The files whose changes make diff marks; all others - templates, plot
# code, data - are taken from the new version as they are.
DIFF_FILES := esdm.typ chapters/*.typ presentations/esdm_presentation.typ

FIGURES := $(patsubst %.drawio,%.svg,$(wildcard figures/*.drawio)) \
	   $(patsubst %.puml,%.svg,$(wildcard figures/*.puml))

TYPST_SOURCES = $(shell find . -path ./$(BUILD) -prune -o \( -name '*.typ' \
	-o -name '*.bib' -o -name '*.csl' -o -name '*.csv' \) -print)

# Compile $1 to $2 with $3 as the root, failing on any output of typst:
# it prints nothing but errors and warnings.
define typst-compile
	@mkdir -p $(dir $2)
	$(TYPST) compile --root $3 $1 $2 2>$2.log || { cat $2.log >&2; rm -f $2 $2.log; exit 1; }
	@if [ -s $2.log ]; then cat $2.log >&2; rm -f $2 $2.log; exit 1; fi
	@rm -f $2.log
endef

.PHONY: all figures diff clean
.DELETE_ON_ERROR:

all: $(foreach d,$(DOCS),$(OUT)/$(d).pdf)

figures: $(FIGURES)

# drawio names the gradients of a figure with a random ID: the name of the
# figure in its place keeps the SVG, and so the PDFs, the same every build.
figures/%.svg: figures/%.drawio
	$(DRAWIO) $(DRAWIO_FLAGS) -o $@.tmp.svg $<
	sed 's/drawio-svg-[A-Za-z0-9_-]\{20\}-/drawio-svg-$*-/g' $@.tmp.svg >$@
	@rm -f $@.tmp.svg

figures/%.svg: figures/%.puml
	$(PLANTUML) -headless -tsvg -pipe <$< >$@

$(OUT)/%.pdf: $(FIGURES) $(TYPST_SOURCES)
	$(call typst-compile,$($*_SRC),$@,.)

# The old version is this directory as of REV, extracted with git archive
# into $(BUILD)/old and given its figures by this Makefile. git archive runs
# in the top directory: in a subdirectory it would only archive what lies
# below it in the tree given. typstdiff.py merges the old version with the
# working tree into $(BUILD)/diff, whose documents show what was deleted
# struck through in red and what was inserted underlined in green, with
# change bars in the margin.
diff: $(FIGURES)
	rm -rf $(BUILD)/old $(BUILD)/old.tar $(BUILD)/diff
	mkdir -p $(BUILD)/old
	$(GIT) -C "$$($(GIT) rev-parse --show-toplevel)" archive --format=tar \
		-o "$(abspath $(BUILD))/old.tar" \
		'$(REV):'"$$($(GIT) rev-parse --show-prefix)"
	tar -x -f $(BUILD)/old.tar -C $(BUILD)/old
	$(MAKE) -C $(BUILD)/old -f $(CURDIR)/Makefile figures
	$(PYTHON) ../tools/typstdiff.py --old $(BUILD)/old --new . \
		--out $(BUILD)/diff --exclude '$(BUILD)' --exclude '*.pdf' \
		--label-old '$(LABEL_OLD)' --label-new '$(LABEL_NEW)' \
		$(foreach f,$(DIFF_FILES),--diff '$(f)')
	$(call typst-compile,$(BUILD)/diff/$(esdm_SRC),$(OUT)/esdm-diff.pdf,$(BUILD)/diff)
	$(call typst-compile,$(BUILD)/diff/$(esdm_presentation_SRC),$(OUT)/esdm_presentation-diff.pdf,$(BUILD)/diff)

clean:
	rm -rf $(BUILD) $(FIGURES) $(foreach d,$(DOCS),$(OUT)/$(d).pdf) \
		$(OUT)/esdm-diff.pdf $(OUT)/esdm_presentation-diff.pdf
