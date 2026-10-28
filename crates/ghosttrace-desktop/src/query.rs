//! Read-only query worker for the desktop (plan P6.2).
//!
//! Timeline pages, histogram aggregates, and event details are read on their
//! own thread with their own [`CaseReader`], so a running capture or import
//! never delays a query and a query never touches SQLite in a render callback.
//! Every request carries the generation that asked for it; the UI drops results
//! whose generation no longer matches.

use std::path::Path;
use std::sync::mpsc::{Receiver, Sender, channel};

use ghosttrace_core::domain::detail::{EventDetail, Histogram};
use ghosttrace_core::domain::query::{EventPage, EventQuery};
use ghosttrace_core::error::CoreError;
use ghosttrace_core::storage::read::CaseReader;
use ghosttrace_core::storage::search::{search_events, validate_search_text};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryTarget {
    Events,
    Histogram,
    Detail,
}

#[derive(Debug, Clone)]
pub enum QueryRequest {
    /// Point the worker at one case database. Sent when a case is created or
    /// opened; a later request replaces the reader.
    SetCase {
        database_path: String,
        display_timezone: String,
    },
    Events {
        generation: u64,
        query: EventQuery,
        /// Raw search text; the worker validates the grammar itself.
        text: Option<String>,
    },
    Histogram {
        generation: u64,
        query: EventQuery,
        text: Option<String>,
        bins: u32,
    },
    Detail {
        generation: u64,
        revision: String,
        event_id: String,
    },
}

#[derive(Debug, Clone)]
pub enum QueryResult {
    Events {
        generation: u64,
        page: Box<EventPage>,
    },
    Histogram {
        generation: u64,
        histogram: Box<Histogram>,
    },
    Detail {
        generation: u64,
        detail: Box<EventDetail>,
    },
    /// A rejected request or read failure. Generation `0` means the failure is
    /// not tied to one query (for example the case database could not open).
    Failed {
        generation: u64,
        target: QueryTarget,
        code: String,
        message: String,
    },
}

pub struct QueryWorker {
    requests: Sender<QueryRequest>,
    results: Receiver<QueryResult>,
}

impl QueryWorker {
    /// Start the query thread. It exits when the worker is dropped.
    pub fn spawn() -> std::io::Result<Self> {
        let (request_tx, request_rx) = channel();
        let (result_tx, result_rx) = channel();
        std::thread::Builder::new()
            .name("ghosttrace-desktop-query".into())
            .spawn(move || worker(request_rx, result_tx))?;
        Ok(Self {
            requests: request_tx,
            results: result_rx,
        })
    }

    pub fn send(&self, request: QueryRequest) {
        let _ = self.requests.send(request);
    }

    /// Non-blocking drain; the render loop never waits for a query.
    pub fn try_recv(&self) -> Option<QueryResult> {
        self.results.try_recv().ok()
    }
}

struct OpenCase {
    reader: CaseReader,
    display_timezone: String,
}

fn worker(requests: Receiver<QueryRequest>, results: Sender<QueryResult>) {
    let mut open: Option<OpenCase> = None;
    while let Ok(request) = requests.recv() {
        let result = match request {
            QueryRequest::SetCase {
                database_path,
                display_timezone,
            } => match CaseReader::open(Path::new(&database_path)) {
                Ok(reader) => {
                    open = Some(OpenCase {
                        reader,
                        display_timezone,
                    });
                    continue;
                }
                Err(error) => failure(0, QueryTarget::Events, &error),
            },
            QueryRequest::Events {
                generation,
                query,
                text,
            } => {
                let Some(case) = &open else {
                    if results
                        .send(failure(0, QueryTarget::Events, &no_case()))
                        .is_err()
                    {
                        return;
                    }
                    continue;
                };
                match read_events(case, &query, text.as_deref()) {
                    Ok(page) => QueryResult::Events {
                        generation,
                        page: Box::new(page),
                    },
                    Err(error) => failure(generation, QueryTarget::Events, &error),
                }
            }
            QueryRequest::Histogram {
                generation,
                query,
                text,
                bins,
            } => {
                let Some(case) = &open else {
                    if results
                        .send(failure(0, QueryTarget::Histogram, &no_case()))
                        .is_err()
                    {
                        return;
                    }
                    continue;
                };
                let text = match optional_search(text.as_deref()) {
                    Ok(text) => text,
                    Err(error) => {
                        if results
                            .send(failure(generation, QueryTarget::Histogram, &error))
                            .is_err()
                        {
                            return;
                        }
                        continue;
                    }
                };
                match case.reader.event_histogram(&query, text.as_ref(), bins) {
                    Ok(histogram) => QueryResult::Histogram {
                        generation,
                        histogram: Box::new(histogram),
                    },
                    Err(error) => failure(generation, QueryTarget::Histogram, &error),
                }
            }
            QueryRequest::Detail {
                generation,
                revision,
                event_id,
            } => {
                let Some(case) = &open else {
                    if results
                        .send(failure(0, QueryTarget::Detail, &no_case()))
                        .is_err()
                    {
                        return;
                    }
                    continue;
                };
                match case.reader.event_detail(&revision, &event_id) {
                    Ok(detail) => QueryResult::Detail {
                        generation,
                        detail: Box::new(detail),
                    },
                    Err(error) => failure(generation, QueryTarget::Detail, &error),
                }
            }
        };
        if results.send(result).is_err() {
            return;
        }
    }
}

fn read_events(
    case: &OpenCase,
    query: &EventQuery,
    text: Option<&str>,
) -> Result<EventPage, CoreError> {
    match optional_search(text)? {
        Some(text) => search_events(&case.reader, &case.display_timezone, query, &text),
        None => case.reader.query_events(&case.display_timezone, query),
    }
}

fn optional_search(
    text: Option<&str>,
) -> Result<Option<ghosttrace_core::storage::search::FtsQuery>, CoreError> {
    match text.map(str::trim).filter(|text| !text.is_empty()) {
        Some(text) => validate_search_text(text).map(Some),
        None => Ok(None),
    }
}

fn no_case() -> CoreError {
    CoreError::InvalidInput("no case is open for this query".into())
}

fn failure(generation: u64, target: QueryTarget, error: &CoreError) -> QueryResult {
    QueryResult::Failed {
        generation,
        target,
        code: error.code().to_string(),
        message: error.to_string(),
    }
}
