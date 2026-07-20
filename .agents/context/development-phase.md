# Development Phase

## Current Status

**IMPORTANT: This project is in EARLY ACTIVE DEVELOPMENT (Pre-Alpha)**

**Status:** Foundational architecture and data models are being established. No production deployment exists yet.

## Development Constraints

### What You Can Do Freely

- ✅ **Make breaking changes freely** - No backward compatibility required
- ✅ **Refactor aggressively** - Improve design without preservation concerns
- ✅ **Remove deprecated code immediately** - Don't keep "for compatibility"
- ✅ **Rename things as needed** - Clear names matter more than continuity
- ✅ **Restructure as needed** - Get the architecture right before building everything

### What You Should NOT Do

- ❌ **Do NOT add backward compatibility layers** - Wastes effort at this stage
- ❌ **Do NOT use "deprecated" markers** - Just remove or fix the code
- ❌ **Do NOT reference "legacy" or "old" in docs** - Everything is current
- ❌ **Do NOT use "New" language in docs** - It's all new, focus on what it IS
- ❌ **Do NOT preserve old patterns** - If you find a better way, change it

## When Backward Compatibility Matters

**Only after first stable release (v1.0.0) with production deployments.**

Until then, prioritize getting the design right over maintaining compatibility.

## Current Focus

**Get the architecture and data models correct before building all the flows and tasks.**

This means:
- Focus on solid foundations
- Validate design decisions early
- Don't rush to implement everything
- It's better to refactor now than later

## Implications for Your Work

When working on this project:

1. **Don't hesitate to suggest breaking changes** if they improve the design
2. **Remove old code immediately** when refactoring (don't leave it commented out)
3. **Update documentation** to reflect current state only (no historical references)
4. **Question existing patterns** if you see better approaches
5. **Prioritize clarity** over continuity
