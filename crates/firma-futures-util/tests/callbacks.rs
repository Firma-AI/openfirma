use std::future::Future;
use std::rc::Rc;

use firma_futures_util::{AsyncFunc, AsyncFuncMut, AsyncFuncOnce};

fn require_send<F: Future + Send>(future: F) -> F {
    future
}

async fn call_once<F>(callback: F, input: &mut String) -> String
where
    F: for<'a> AsyncFuncOnce<&'a mut String, String, Fut: Send>,
{
    callback(input).await
}

async fn call_mut<F: AsyncFuncMut<u32, u32, Fut: Send>>(mut callback: F) -> [u32; 2] {
    [callback(3).await, callback(7).await]
}

async fn call_shared<F: AsyncFunc<(u32, u32), u32, Fut: Send>>(callback: F) -> [u32; 2] {
    [callback((3, 7)).await, callback((7, 3)).await]
}

#[tokio::test]
async fn once_callback_borrows_argument_and_external_data_while_consuming_owned_capture() {
    let mut input = String::from("input:");
    let suffix = String::from("borrowed");
    let borrowed = &suffix;
    let owned = String::from("owned result");
    let result = require_send(call_once(
        async move |input| {
            tokio::task::yield_now().await;
            input.push_str(borrowed);
            owned
        },
        &mut input,
    ))
    .await;
    assert_eq!(result, "owned result");
    assert_eq!(input, "input:borrowed");
    assert_eq!(suffix, "borrowed");
}

#[tokio::test]
async fn mutable_callback_retains_state_between_non_lending_futures() {
    let mut total = 11;
    let result = require_send(call_mut(move |increment| {
        total += increment;
        let current = total;
        async move {
            tokio::task::yield_now().await;
            current
        }
    }))
    .await;
    assert_eq!(result, [14, 21]);
}

#[tokio::test]
async fn shared_callback_reuses_captured_data_and_tuple_arguments() {
    let multiplier = 5;
    let result = require_send(call_shared(move |(left, right)| async move {
        tokio::task::yield_now().await;
        left * multiplier + right
    }))
    .await;
    assert_eq!(result, [22, 38]);
}

#[tokio::test]
async fn local_futures_are_allowed_without_a_send_bound() {
    async fn call_local<F: AsyncFuncOnce<(), usize>>(callback: F) -> usize {
        callback(()).await
    }

    let result = call_local(async |()| {
        let value = Rc::new(String::from("local"));
        tokio::task::yield_now().await;
        value.len()
    })
    .await;
    assert_eq!(result, 5);
}
