# CLAUDE.md

This file provides guidance to LLM agents when working with code in this repository.

## Core principles

The implementation must strictly adhere to these non-negotiable principles, as established in previous PRDs:

1. **DRY (don't Repeat yourself)**

   - Zero code duplication will be tolerated
   - Each functionality must exist in exactly one place
   - No duplicate files or alternative implementations allowed

2. **KISS (keep it simple, stupid)**

   - Implement the simplest solution that works
   - No over-engineering or unnecessary complexity
   - Straightforward, maintainable code patterns

3. **Clean file system**

   - All existing files must be either used or removed
   - No orphaned, redundant, or unused files
   - Clear, logical organization of the file structure

4. **Transparent error handling**

   - No error hiding or fallback mechanisms that mask issues
   - All errors must be properly displayed to the user
   - Errors must be clear, actionable, and honest

5. **No obvious comments**

   - Code comments that can easily be inferred by a reasonably competent engineer are unnecessary, they create more lines of code without aiding understanding.

## Success Criteria

In accordance with the established principles and previous PRDs, the implementation will be successful if:

1. **Zero Duplication**: No duplicate code or files exist in the codebase
2. **Single Implementation**: Each feature has exactly one implementation
3. **No Fallbacks**: No fallback systems that hide or mask errors
4. **Transparent Errors**: All errors are properly displayed to users
5. **Component Architecture**: UI is built from reusable, modular components

## Code Style

- Format code with `cargo fmt`
