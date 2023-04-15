import { HttpClient, HttpParams } from "@angular/common/http";
import { map } from "rxjs";
import { PaginationResult } from "../_models/pagination";

export function getPaginatedResult<T>(url: string, params: HttpParams,http : HttpClient) {
    const paginatedResult: PaginationResult<T> = new PaginationResult<T>;

    return http.get<T>(url, { observe: 'response', params }).pipe(
        map(response => {
            if (response.body) {
                paginatedResult.result = response.body;
            }
            const pagintaion = response.headers.get('Pagination');
            if (pagintaion) {
                paginatedResult.pagination = JSON.parse(pagintaion);
            }
            return paginatedResult;
        })
    );
}

export function getPaginationHeaders(pageNumber: number, pageSize: number) {
    let params = new HttpParams();

    params = params.append('pageNumber', pageNumber);
    params = params.append('pageSize', pageSize);

    return params;
}