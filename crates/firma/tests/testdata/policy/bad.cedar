// Syntactically invalid Cedar: missing comma after `principal` and an
// unbalanced paren. Exercises the parse-error line:column diagnostic path.
permit(principal action, resource;
