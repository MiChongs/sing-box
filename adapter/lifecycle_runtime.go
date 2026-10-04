package adapter

// RuntimeComponentRemover is implemented by the outbound and endpoint
// managers. Outbound providers replace and drop their members while the box is
// running; the core manager interfaces have no hot reload, so providers reach
// this through a type assertion.
type RuntimeComponentRemover interface {
	Remove(tag string) error
}

// StartRuntimeComponent starts a component created after its manager has
// started, running every start stage through the manager scope at once. On
// failure the component is closed again.
func StartRuntimeComponent(scope *Scope, name string, component Lifecycle) error {
	for _, stage := range ListStartStages {
		err := scope.Start(name, component, stage)
		if err != nil {
			_ = scope.CloseChild(component)
			return err
		}
	}
	return nil
}

// CloseRuntimeComponent closes a component that is replaced or removed while
// its manager is running. Components that are not lifecycles hold nothing to
// release.
func CloseRuntimeComponent(scope *Scope, component any) error {
	lifecycle, isLifecycle := component.(Lifecycle)
	if !isLifecycle || scope == nil {
		return nil
	}
	return scope.CloseChild(lifecycle)
}
