//! Stable async callback bounds with a nameable concrete future.
//!
//! [`AsyncFuncOnce`], [`AsyncFuncMut`], and [`AsyncFunc`] expose the future as
//! [`AsyncFuncOnce::Fut`], so consumers can require `Fut: Send` without boxing or
//! accessing unstable associated types on the standard async callable traits.
//! The future is not required to be [`Send`] unless the consumer requests it.
//!
//! Each trait takes one argument type: use `()` for no inputs and a tuple for
//! multiple inputs. Higher-ranked argument bounds can select a different future
//! type for each borrow lifetime.
//!
//! Reusable callbacks must also implement ordinary [`FnMut`] or [`Fn`]. These
//! traits do not cover lending async closures whose futures borrow captured
//! closure state. Such closures can still be consumed once with
//! [`AsyncFuncOnce`].

use std::future::Future;

/// Async callback that can be consumed once, exposing its returned future.
///
/// The [`FnOnce`] bound names the future without unstable access to
/// `AsyncFnOnce::CallOnceFuture`. The [`AsyncFnOnce`] bound preserves async
/// closure argument inference.
///
/// A [`Send`] callback can still return a non-`Send` future. An explicit future
/// bound rejects values retained across an await that cannot cross threads:
///
/// ```compile_fail
/// use firma_futures_util::AsyncFuncOnce;
/// use std::rc::Rc;
///
/// fn require_send<F: AsyncFuncOnce<(), i32, Fut: Send>>(_: F) {}
/// require_send(async |()| {
///     let value = Rc::new(42);
///     std::future::pending::<()>().await;
///     *value
/// });
/// ```
pub trait AsyncFuncOnce<A, R>:
    AsyncFnOnce(A) -> R + FnOnce(A) -> <Self as AsyncFuncOnce<A, R>>::Fut
{
    /// Concrete future returned by an invocation with argument type `A`.
    type Fut: Future<Output = R>;
}

impl<F, A, R, Fut> AsyncFuncOnce<A, R> for F
where
    F: AsyncFnOnce(A) -> R + FnOnce(A) -> Fut,
    Fut: Future<Output = R>,
{
    type Fut = Fut;
}

/// Async callback callable repeatedly through a mutable reference.
///
/// The [`FnMut`] bound requires a non-lending future type. The callback may
/// update captured state before constructing that future, but the future must
/// not borrow the callback itself. Its argument may still contain borrowed data.
///
/// [`AsyncFuncOnce::Fut`] can be bounded for each invocation:
///
/// ```compile_fail
/// use firma_futures_util::AsyncFuncMut;
/// use std::rc::Rc;
///
/// fn require_send<F: AsyncFuncMut<(), i32, Fut: Send>>(_: F) {}
/// require_send(|()| async {
///     let value = Rc::new(42);
///     std::future::pending::<()>().await;
///     *value
/// });
/// ```
pub trait AsyncFuncMut<A, R>:
    AsyncFuncOnce<A, R> + AsyncFnMut(A) -> R + FnMut(A) -> <Self as AsyncFuncOnce<A, R>>::Fut
{
}

impl<F, A, R> AsyncFuncMut<A, R> for F where
    F: AsyncFuncOnce<A, R> + AsyncFnMut(A) -> R + FnMut(A) -> <Self as AsyncFuncOnce<A, R>>::Fut
{
}

/// Async callback callable repeatedly through a shared reference.
///
/// Like [`AsyncFuncMut`], this requires a non-lending future via the ordinary
/// [`Fn`] bound. Use [`AsyncFuncOnce`] when a lending closure only runs once.
///
/// A future's thread-safety is independent of the callback's thread-safety:
///
/// ```compile_fail
/// use firma_futures_util::AsyncFunc;
/// use std::rc::Rc;
///
/// fn require_send<F: AsyncFunc<(), i32, Fut: Send>>(_: F) {}
/// require_send(|()| async {
///     let value = Rc::new(42);
///     std::future::pending::<()>().await;
///     *value
/// });
/// ```
pub trait AsyncFunc<A, R>:
    AsyncFuncMut<A, R> + AsyncFn(A) -> R + Fn(A) -> <Self as AsyncFuncOnce<A, R>>::Fut
{
}

impl<F, A, R> AsyncFunc<A, R> for F where
    F: AsyncFuncMut<A, R> + AsyncFn(A) -> R + Fn(A) -> <Self as AsyncFuncOnce<A, R>>::Fut
{
}
