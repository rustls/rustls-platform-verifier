//! A small wrapper over interacting with the JNI in a type-safe way.

use jni::errors::Error as JNIError;
use jni::objects::{GlobalRef, JClass, JObject, JValue};
use jni::{JNIEnv, JavaVM};
use once_cell::sync::OnceCell;

static GLOBAL: OnceCell<Global> = OnceCell::new();

/// A layer to access the Android runtime which is hosting the current
/// application process.
///
/// Generally this trait should be implemented in your Rust app component's FFI
/// initialization layer.
pub trait Runtime: Send + Sync {
    /// Returns a handle to the current process' JVM.
    fn java_vm(&self) -> &JavaVM;
    /// Returns a reference to the current app's [Context].
    ///
    /// [Context]: <https://developer.android.com/reference/android/content/Context>
    fn context(&self) -> &GlobalRef;
    /// Returns a reference to the class returned by the current JVM's `getClassLoader` call.
    fn class_loader(&self) -> &GlobalRef;
}

enum Global {
    Internal {
        java_vm: JavaVM,
        context: GlobalRef,
        loader: GlobalRef,
    },
    External(&'static dyn Runtime),
}

impl Global {
    fn env(&self) -> Result<JNIEnv, Error> {
        let vm = match self {
            Global::Internal { java_vm, .. } => java_vm,
            Global::External(global) => global.java_vm(),
        };
        Ok(vm.attach_current_thread_permanently()?)
    }

    fn context(&self) -> Result<Context, Error> {
        let env = self.env()?;

        let context = match self {
            Global::Internal { context, .. } => context,
            Global::External(global) => global.context(),
        };

        let loader = match self {
            Global::Internal { loader, .. } => loader,
            Global::External(global) => global.class_loader(),
        };

        Ok(Context {
            env,
            context: JObject::from(context),
            loader: JObject::from(loader),
        })
    }
}

fn global() -> &'static Global {
    GLOBAL
        .get()
        .expect("Expect rustls-platform-verifier to be initialized")
}

/// Initializes and stores the required context for the Android platform.
///
/// This method will setup and store an envrionment locally. This is useful if
/// nothing else in your application needs access the Android runtime.
///
/// Initialization must be done before any verification is attempted.
pub fn init_hosted(env: &JNIEnv, context: JObject) -> Result<(), JNIError> {
    GLOBAL.get_or_try_init(|| -> Result<_, JNIError> {
        let loader =
            env.call_method(context, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?;
        let global = Global::Internal {
            java_vm: env.get_java_vm()?,
            context: env.new_global_ref(context)?,
            loader: env.new_global_ref(JObject::try_from(loader)?)?,
        };

        Ok(global)
    })?;

    Ok(())
}

/// Initializes and stores the required context for the Android platform.
///
/// This method utilizes an existing Android runtime envrionment and set anything
/// else up on its own. This is useful if your application already interacts with
/// the runtime and has pre-existing handles.
///
/// This function will never panic, and is therefore safe to use at FFI boundaries.
///
/// Initialization must be done before any verification is attempted.
pub fn init_external(runtime: &'static dyn Runtime) {
    GLOBAL.get_or_init(|| Global::External(runtime));
}

/// Wrapper for JNI errors that will log and clear exceptions
/// It should generally be preferred to `jni::errors::Error`
#[derive(Debug)]
pub(super) struct Error;

impl From<JNIError> for Error {
    #[track_caller]
    fn from(cause: JNIError) -> Self {
        if let JNIError::JavaException = cause {
            if let Ok(env) = global().env() {
                // These should not fail if we are already in a throwing state unless
                // things are very broken. In that case, there isn't much we can do.
                let _ = env.exception_describe();
                let _ = env.exception_clear();
            }
        }

        Self
    }
}

pub(super) struct Context<'a> {
    env: JNIEnv<'a>,
    context: JObject<'a>,
    loader: JObject<'a>,
}

impl<'a> Context<'a> {
    /// Borrow a reference to the JNI Environment executing the Android application
    pub(super) fn env(&self) -> &JNIEnv<'a> {
        &self.env
    }

    /// Borrow the `applicationContext` from the Android application
    /// <https://developer.android.com/reference/android/app/Application>
    pub(super) fn application_context(&self) -> &JObject<'a> {
        &self.context
    }

    /// Load a class from the application class loader
    ///
    /// This should be used instead of `JNIEnv::find_class` to ensure all classes
    /// in the application can be found.
    pub(super) fn load_class(&self, name: &str) -> Result<JClass<'a>, Error> {
        let env = self.env();
        let name = env.new_string(name)?;
        let class = env.call_method(
            self.loader,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            &[JValue::from(name)],
        )?;

        Ok(JObject::try_from(class)?.into())
    }
}

/// Borrow the Android application context and execute the closure
/// `with_context, ensuring locals are properly freed and exceptions
/// are cleared.
pub(super) fn with_context<F, T>(f: F) -> Result<T, Error>
where
    F: FnOnce(&Context) -> Result<T, Error>,
{
    let context = global().context()?;
    let env = context.env();

    // 16 is the default capacity in the JVM, we can make this configurable if necessary
    env.push_local_frame(16)?;

    let res = f(&context);

    env.pop_local_frame(JObject::null())?;

    res
}

/// Loads and caches a class on first use
pub(super) struct CachedClass {
    name: &'static str,
    class: OnceCell<GlobalRef>,
}

impl CachedClass {
    /// Creates a lazily initialized class reference to the class with `name`.
    pub(super) const fn new(name: &'static str) -> Self {
        Self {
            name,
            class: OnceCell::new(),
        }
    }

    /// Gets the cached class reference, loaded on first use
    pub(super) fn get<'a: 'b, 'b>(&'a self, cx: &Context<'b>) -> Result<JClass<'b>, Error> {
        let class = self.class.get_or_try_init(|| -> Result<_, Error> {
            let class = cx.load_class(self.name)?;

            Ok(cx.env().new_global_ref(class)?)
        })?;

        Ok(JClass::from(class.as_obj()))
    }
}
