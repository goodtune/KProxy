import { useEffect } from 'react';

/**
 * Custom hook to set the data-page attribute on the body element.
 * This is used by E2E tests to identify which page is currently active.
 *
 * @param {string} pageId - The unique identifier for the page
 */
const usePageId = (pageId) => {
  useEffect(() => {
    document.body.setAttribute('data-page', pageId);

    return () => {
      document.body.removeAttribute('data-page');
    };
  }, [pageId]);
};

export default usePageId;
